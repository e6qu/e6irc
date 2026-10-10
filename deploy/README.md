# Deploying e6irc

A typical deployment runs e6irc as a container behind a TLS-terminating
reverse proxy or HTTP gateway, with its own database on a shared PostgreSQL
and an OpenID Connect provider such as Shauth as its SSO source.

The image is host-neutral: nothing in it knows about AWS.
[Running on any container host](#running-on-any-container-host) states what a
host has to provide; the AWS deployment above is the worked example of it, and
the only one this repository describes step by step.

## Image

`Dockerfile` builds the Vite frontend and embeds it into `e6ircd` before
copying the complete server onto a distroless base
(`gcr.io/distroless/cc-debian12`). No build tool or startup
build step exists in the runtime image. The `.github/workflows/release.yml`
workflow publishes `ghcr.io/e6qu/e6irc:<short-sha>` plus the direct
`<short-sha>-amd64` and `<short-sha>-arm64` images for every commit on `main`
whose CI run succeeded: the workflow is triggered by the completion of CI, not
by the push, and builds the exact commit CI verified. A commit whose CI failed,
or was cancelled because a newer push overtook it, is never published.
It publishes no mutable branch or `latest` tag and retains the newest 20
release groups, including their untagged provenance and
software-bill-of-materials referrers.

Each architecture digest carries signed GitHub build provenance and an SPDX
software bill of materials as Open Container Initiative referrers; the assembled commit-SHA manifest
carries signed assembly provenance. The daemon is built with `cargo auditable`,
so the software bill of materials names every Rust crate compiled into it and a
RUSTSEC scan of the image (or of the extracted binary) sees them. Verify the
attestations after authenticating `gh` for the repository. Name the signing
workflow and the ref it ran on, not only the repository: any workflow in the
repository can sign for it, and only `release.yml` running on `main` publishes
images.

```sh
gh attestation verify oci://ghcr.io/e6qu/e6irc:<short-sha> -R e6qu/e6irc \
  --signer-workflow e6qu/e6irc/.github/workflows/release.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners
gh attestation verify oci://ghcr.io/e6qu/e6irc:<short-sha>-amd64 -R e6qu/e6irc \
  --signer-workflow e6qu/e6irc/.github/workflows/release.yml \
  --source-ref refs/heads/main --deny-self-hosted-runners \
  --predicate-type https://spdx.dev/Document/v2.3
```

## Native archives

A Git tag exactly matching `v<workspace-version>`, on a commit that has a
successful CI run on `main`, publishes deterministic
archives for Linux, macOS, and Windows on x86-64 and ARM64. Every archive
contains the daemon, CLI, TUI, README, license, and systemd unit. Download the
archive for the host together with `SHA256SUMS`, then verify both transport
integrity and GitHub build provenance — signed by `release.yml` running on
that exact tag:

```sh
grep 'e6irc-0.1.0-x86_64-unknown-linux-gnu.tar.gz$' SHA256SUMS \
  | sha256sum --check
gh attestation verify e6irc-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  -R e6qu/e6irc \
  --signer-workflow e6qu/e6irc/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0 --deny-self-hosted-runners
```

The native binaries are built with `cargo auditable` too, by the Rust release
the image's build stage carries, from a clean build directory.

The archives use the target's normal dynamic runtime; they are not musl/static
packages. On Linux, extract the archive and use its systemd unit as below.

## Native Linux service

`e6ircd.service` is the validated systemd installation contract. Install the
server at `/usr/local/bin/e6ircd`, create a locked-down `e6irc` system user and
group, place the configuration at `/etc/e6irc/e6ircd.toml` with any referenced
key/certificate files readable by that account, then install and enable the
unit:

```sh
sudo install -D -m 0755 target/release/e6ircd /usr/local/bin/e6ircd
sudo useradd --system --home-dir /nonexistent --shell /usr/sbin/nologin e6irc
sudo install -d -o root -g e6irc -m 0750 /etc/e6irc
sudo install -o root -g e6irc -m 0640 e6ircd.toml /etc/e6irc/e6ircd.toml
sudo install -m 0644 deploy/e6ircd.service /etc/systemd/system/e6ircd.service
sudo systemctl daemon-reload
sudo systemctl enable --now e6ircd
```

The unit uses SIGTERM and a 150-second stop budget, exceeding the daemon’s
bounded shutdown — in edge mode up to 84 seconds handing every client over to
the next core, then up to 15 seconds telling every bouncer network's upstream
goodbye, then up to 5 seconds draining the core shards, then up to 8 seconds
letting client connections deliver their closing `ERROR`, then up to 30
seconds flushing PostgreSQL ([Stop timeout](#stop-timeout)) — so systemd cannot
kill a still-clean shutdown, or a handover, first. It sets `StartLimitIntervalSec=0`: a refused database connection fails the
daemon in milliseconds, and systemd's default limit of five starts in ten
seconds would otherwise leave the unit permanently failed after a reboot where
PostgreSQL comes up later than e6irc; restarts stay two seconds apart and each
attempt is a journal line. It grants no capabilities, makes the host filesystem read-only
to the process, gives it private pseudo-devices and only its own `/proc`
entries, forbids new namespaces, and restricts it to native-architecture system
calls in systemd's `@system-service` set (a call outside it fails with `EPERM`
rather than killing the daemon); listeners on privileged ports therefore need a
reverse proxy or an explicit, reviewed service override. It sets `LimitCORE=0`,
and the daemon also marks itself non-dumpable at start
(`prctl(PR_SET_DUMPABLE, 0)`, with a warning line if that fails): its memory
holds the master key, opened upstream credentials, and session tokens, and
neither a core file nor a same-user debugger may read them.

### TLS certificates

A `[[listeners]]` entry with `tls` and the BNC attach listener's certificate
(`[bnc].tls`, or the console's BNC TLS paths) are read from their PEM files at
start and again whenever they change: every 60 seconds the daemon compares
each file's modification time and a SHA-256 digest of its contents with those
it read — the digest decides, so a rewrite that keeps the modification time
(`cp -p`, `rsync -t`, an unpacked archive) is still a change — and it reloads
at once on `SIGHUP`
(`systemctl kill -s HUP e6ircd`). A renewal hook therefore needs no restart.
The `SIGHUP` handler is installed before the database wait, so a renewal hook
that fires while the daemon is still starting cannot kill it.
A reload that fails — a half-written file, a key that does not belong to the
certificate — keeps the certificate already being served and logs
`ERROR: TLS certificate … could not be reloaded` with the reason, once per
distinct failure; the files are then read again at every check until they load,
so a fix is picked up within a minute however it was written (`SIGHUP` retries
at once). Each successful reload is a log line naming the files.

### BNC attach listener

Clients attaching to their always-on networks authenticate with their account
password (SASL PLAIN). The listener therefore refuses to be configured on any
address but loopback without a certificate — in the configuration file
(`[bnc] addr = …` needs `tls = { cert_path = …, key_path = … }` unless the
address is a loopback one — anywhere in `127.0.0.0/8`, `::1`, or an
IPv4-mapped loopback address such as `::ffff:127.0.0.1`) and in the console
alike, each refusal naming the
setting. A loopback listener without TLS is for clients on the same machine
(or behind a TLS-terminating proxy that runs there). The TLS handshake has the
same 30-second bound as the IRC listeners'.

## Bootstrap configuration (environment)

The daemon refuses to connect a bouncer network to an upstream inside its own
network — loopback, RFC 1918, carrier-grade NAT, unique-local — at every
ingress and again at dial time, because an account holder chooses the upstream
address. The container exposes no variable to change that; a configuration
file's `internal_upstreams = "allow"` exists for test harnesses whose upstreams
listen on loopback.

The image is distroless: it contains the daemon, glibc, and CA certificates —
no shell, no package manager, no script. Its command is `e6ircd
--config-from-environment`: the daemon builds its bootstrap configuration from
the environment itself, in memory, and puts it through exactly the parser and
validation a configuration file gets (the deployment injects secrets —
`E6IRC_DATABASE_URL`, `E6IRC_OIDC_CLIENT_SECRET` — from AWS Secrets Manager).
Nothing is written to disk, so there is no secrets-bearing file to protect or
to find. A host that prefers a file mounts one and replaces the command with
`--config /path/to/e6irc.toml`; such a container must also set
`E6IRC_HTTP_ADDR` to the file's `[http].addr` (or override the health check
with `e6ircd healthcheck --addr ip:port`), because the probe reads the
environment, not the file. `e6ircd check-config --config-from-environment`
validates the environment and exits; it checks everything start would refuse
short of reaching the network or PostgreSQL, `E6IRC_MONITORING_TOKEN` and every
configured TLS certificate/key pair included. It cannot check agreement with
the settings the console stores (below), which needs PostgreSQL, and says so
when it passes. Missing required values fail the
container loudly rather than starting half-configured, and so do two kinds of
malformed value, each refused by variable name without printing the value: a
control character anywhere in a variable (typically the carriage return or
newline of a line pasted into a secret store), and an `E6IRC_SECURE_COOKIES`
that is not exactly `true` or `false`. Empty fields in `E6IRC_ADMIN_ACCOUNTS`
(a trailing or doubled comma) name no account. `E6IRC_CONFIG_PATH` and
`E6IRC_BINARY`, which the shell entrypoint of earlier images honoured, have
nothing left to mean and are refused rather than ignored. A configuration *file*
that does not parse is reported by line, column, and reason, never by quoting
the line, which may hold a secret. On the first database-backed start,
operational values are imported into the revisioned `server_settings` row.
After that the console owns them and administrators manage them at
`/console/configuration`: the server name, network name, IRC address, public
URL, cookie policy, administrator accounts (`E6IRC_ADMIN_ACCOUNTS`) and the
OpenID Connect provider (client secret included). Only the database URL,
secrets-key source, HTTP bind, immutable release revision, and the one-time
first-administrator token stay bootstrap-only, because the console depends on
them. A variable that still states a console-owned setting must agree with the
stored value: if it differs, the container fails to start and names each such
setting (`http.admin_accounts`, `oidc[0].client_secret`) without printing
either value. Resolve it by unsetting the variable (the stored value applies;
an unset `E6IRC_SERVER_NAME` or `E6IRC_PUBLIC_URL` takes the stored value, and
only a first start, with nothing stored, needs it),
setting it to the stored value, or changing the setting in the console first.
So removing a name from `E6IRC_ADMIN_ACCOUNTS` or rotating
`E6IRC_OIDC_CLIENT_SECRET` is done in the console (then the variable is
aligned or unset) — never silently ignored. A variable left unset is not a
conflict, and neither is the default put in its place. An administrator locked
out of the console uses `e6ircd recover-administrator`. On an empty account
store, set `E6IRC_BOOTSTRAP_TOKEN`, open `/bootstrap`, and create the first
durable administrator. The route closes permanently as soon as any account
exists; remove the environment secret after successful initialization.
The same page owns live history and audit retention (30 and 365 days by
default). History retention bounds both the server's own channel history
(`messages`) and every network's bouncer history (`bnc_buffer`, direct
messages included), and what either serves from memory — the core's history
rings and each network's in-memory backlog — from the moment it is saved. A
supervised worker applies those limits to the database in bounded
batches every five minutes — up to 21 batches in one tick when a backlog has
built up — and also removes expired browser sessions, personal access tokens,
device grants, consumed logout tokens, spent sign-in flows, and monitoring samples past their
retention; operators should alert on its fixed-category database errors rather
than scheduling a second cleanup job.

Deployments that still carry plaintext OIDC/operator credentials need a master
key before the console can own those secrets. Until then, bootstrap credentials
remain authoritative and the UI labels them accordingly. Once a key is
configured, the next start seals and imports them atomically.

| Variable | Required | Meaning |
|---|---|---|
| `E6IRC_SERVER_NAME` | on the first start | IRC server name, e.g. `irc.example.com`; unset afterwards, the name the console stores applies |
| `E6IRC_PUBLIC_URL` | on the first start | External base URL; OIDC redirect + post-logout base; unset afterwards, the URL the console stores applies |
| `E6IRC_DATABASE_URL` | yes (secret) | PostgreSQL URL. Its query keys are a closed set — `host`, `port`, `dbname`, `user`, `password`, `sslmode`, `sslrootcert`, `sslcert`, `sslkey` (or their hyphenated spellings), `application_name`, `options` (`-c name=value` settings), `statement-cache-capacity` — and any other key, a misspelt `sslmode` value or a field stated twice is refused at start; the container must not set libpq variables (`PGHOST`, `PGSSLMODE`, `PGPASSWORD`, ...), which are refused by name: the URL alone describes the connection |
| `APPLICATION_RELEASE_REVISION` | yes | The deployed revision, shown on the console's configuration page and on the authenticated identity page Shauth's browser validator reads. With the `shauth` provider configured it must be 12–64 lowercase hexadecimal digits or `sha256:` plus 64 of them; the image tag's short SHA qualifies |
| `E6IRC_SECRET_KEY` | for credential storage (secret) | Base64 32-byte primary key; new managed and account-network credentials are sealed with it |
| `E6IRC_PREVIOUS_SECRET_KEYS` | only during rotation (secret) | Comma-separated old keys accepted for reads until `e6ircd rotate-secrets` commits |
| `E6IRC_NETWORK_NAME` | no (`e6qu`) | IRC network name |
| `E6IRC_HTTP_ADDR` | no (`0.0.0.0:8080`) | HTTP/REST/WebSocket listen address |
| `E6IRC_IRC_ADDR` | no (`127.0.0.1:6667`) | Raw IRC listener — loopback only; IRC is reached over WebSocket (`/ws/irc`) publicly |
| `E6IRC_SECURE_COOKIES` | no (`true`) | Mark session cookies `Secure`; exactly `true` or `false` |
| `E6IRC_HSTS_INCLUDE_SUBDOMAINS` | no (`false`) | Add `includeSubDomains` to the HSTS header, forcing every sibling host of the domain onto HTTPS for a year; exactly `true` or `false`, and `true` needs an `https://` `E6IRC_PUBLIC_URL` |
| `E6IRC_MONITORING_TOKEN` | no (secret; at least 32 non-whitespace characters) | Bearer for the read-only `/api/v1/monitoring/observation` endpoint; unset, the endpoint is closed |
| `E6IRC_ADMIN_ACCOUNTS` | no | Comma-separated administrator account names, imported on the first start and console-owned afterwards (see above); empty fields name no account |
| `E6IRC_TRUSTED_PROXIES` | no | Comma-separated CIDR ranges (`192.0.2.10/32` for one address) of the reverse proxies whose `X-Forwarded-For` names the client (`limits.trusted_proxies`); imported on the first start and console-owned afterwards, so a stated value must match the stored one (see above). A container behind a proxy states it: its listener binds `0.0.0.0`, so start cannot tell that every request comes from the proxy, and every user would share one authentication budget |
| `E6IRC_BOOTSTRAP_TOKEN` | no (secret; 32–512 bytes) | One-time browser token for creating the first durable administrator on an empty account store |
| `E6IRC_DATABASE_MAX_CONNECTIONS` | no (sized to the host) | Most connections the shared PostgreSQL pool opens, 2–200 (`[database] max_connections` in a configuration file). The default is 1 (the serial database worker) + 4 (concurrent Argon2 verifications) + 2 × the host's CPU threads; size the PostgreSQL server's `max_connections` for the serving process's pool, a few connections per standby (see High availability), and your own sessions. The pool's size, idle count and acquire timeouts are on `/api/v1/admin/metrics` (`e6irc_database_pool_*`; administrator authentication required) |
| `E6IRC_OIDC_ISSUER` | no | Shauth issuer, e.g. `https://auth.example.com` (enables SSO) |
| `E6IRC_OIDC_CLIENT_ID` | with issuer | Shauth OIDC client id, e.g. `e6irc-dev` |
| `E6IRC_OIDC_CLIENT_SECRET` | with issuer (secret) | Shauth OIDC client secret |
| `E6IRC_OIDC_NAME` | no (`shauth`) | Provider name (URL segment) |
| `E6IRC_OIDC_END_SESSION` | with issuer | Relying-party-initiated logout endpoint, e.g. `https://auth.example.com/oauth2/sessions/logout` |
| `E6IRC_OIDC_ACCOUNT_CLAIM` | no (`preferred_username`) | ID-token claim that names the e6irc account: `preferred_username` or `email` |
| `E6IRC_OIDC_TOKEN_AUTH` | no (`client_secret_post`) | How the client authenticates at the token endpoint: `client_secret_post` (how Shauth registers managed applications) or `client_secret_basic`. It belongs to the client registration, so discovery cannot report it |

Every `E6IRC_OIDC_*` variable configures the provider `E6IRC_OIDC_ISSUER` names;
one set without the issuer is refused at start rather than ignored.

### Rotate the credential key

Install a newly generated key as `E6IRC_SECRET_KEY`, retain the old value in
`E6IRC_PREVIOUS_SECRET_KEYS`, and restart the service. The new process can read
both generations but writes only with the new primary. The command needs the
same configuration as the running daemon, which in a container is its
environment: run it inside the running container, where a `docker exec` or ECS
Exec session inherits that environment. There is no shell in the image, so the
binary is executed directly:

```sh
docker exec CONTAINER /usr/local/bin/e6ircd rotate-secrets --config-from-environment
```

The command re-seals managed configuration and every account-network
credential in one PostgreSQL transaction and writes a redacted audit record.
It exits nonzero and rolls the whole transaction back if any value cannot be
proven readable. After success, remove `E6IRC_PREVIOUS_SECRET_KEYS` and restart.
The re-seal writes a new settings revision; the serving process hears it and
adopts it at once, so the console keeps saving without a restart. Run
`rotate-secrets` and `recover-administrator` with the binary the serving
process runs: against a schema older than its binary, a command refuses while a
process serves (`upgrade the serving process first`) rather than migrate under
it.

### Recover a lost administrator login

The browser bootstrap closes for good once any account exists. If every
administrator login is lost — a forgotten password, a broken identity provider —
recover on the host, where the configuration and the database already are:

```sh
docker exec CONTAINER /usr/local/bin/e6ircd recover-administrator --account NAME --config-from-environment
# or, natively:
sudo -u e6irc e6ircd recover-administrator --account NAME --config /etc/e6irc/e6ircd.toml
```

It acts on one existing, active account: prints a new password once, grants
durable administrator authority, revokes every credential that account held
(app passwords, personal access tokens, device grants, browser sessions), and
writes an `ADMINISTRATOR_RECOVERY` audit record. An unknown or suspended account
is refused and nothing is changed. A running e6ircd honours the authority at
once — it reads an account's authority on every request — so sign in and change
the password.

## Upgrade notes

Read these before deploying a release that includes the change named.

- **One process serves a database (migration 0098).** The first upgrade to a
  release with the serving lease needs every e6ircd process on the database
  stopped: an older release knows no lease, so one left running would serve
  beside the new one. Stop them all, start one with the new release (it
  migrates), then start any standbys. Every later upgrade is the rolling
  procedure under High availability. A second process on the same database no
  longer serves beside the first: it stands by (below).
- **The HTTP authentication throttle is on (migration 0088).** A stored
  `limits.auth_rate_burst` of `null` used to mean off; it now takes the
  default, twenty requests a minute per client address, on the routes that
  sign people in. Behind a reverse proxy every request comes from the proxy's
  address, so unless `limits.trusted_proxies` (a console-owned limit, at
  `/console/configuration`) names the proxy, every user shares one budget of
  twenty a minute.
  Set `trusted_proxies` to the proxy's address or range so each client is
  counted by the address the proxy forwards, or set `auth_rate_burst` to
  `"off"` if the proxy throttles those routes itself. When the HTTP listener
  binds only a loopback address and no trusted proxy is set, start logs a
  warning saying so; a listener bound wider (`0.0.0.0:8080` in the container)
  cannot tell, so check the setting.
- **The database URL is read strictly.** A query key outside the closed set
  in the table above (`ssl_mode`, `connect_timeout`, `hostaddr`, ...), a
  misspelt `sslmode` value, or a field stated twice now refuses start by name;
  such a key used to be dropped, and a dropped `sslmode` meant no certificate
  verification. libpq variables (`PGSSLMODE`, `PGHOST`, `PGPASSWORD`, ...) in
  the daemon's environment are refused too — state everything in the URL.
- **A server network's `buffer_cap` is at most 5,000 (migration 0091).** That
  is what the stored backlog keeps, and a start now restores a network's whole
  buffer. A stored value above it is brought to 5,000 (more never survived a
  restart), as a new settings revision whose `CONFIG` audit entry records each
  network's previous value; a configuration file stating more is refused at
  start.
- **A configuration file may leave out `server_name`, `network_name` and
  `[[listeners]]`** once the console stores them, and `E6IRC_SERVER_NAME` may be
  unset; the stored values apply. A first start with nothing stored refuses,
  naming each.
- **`E6IRC_PUBLIC_URL` may be unset** once the console stores the public URL,
  as a database-backed file's `[http]` may omit `public_url`; the stored value
  applies. A first start with nothing stored refuses, naming
  `http.public_url` — so a database-backed file with `[http]` states it on the
  first start too.
- **`motd` lines and `description` are bounded** (372 and 242 bytes: what their
  replies carry whole). A longer one is refused at start and at a console
  save instead of being cut short on the wire.
- **The whole MOTD is bounded in bytes (migration 0094).** A new client is
  sent all of it at registration, so it may take at most 8,703 bytes as sent —
  half the smallest SendQ: its lines together at most 8,318 bytes, each line
  counting 140 more for its reply. A stored MOTD above it keeps the longest run
  of its first lines that fits, as a new settings revision whose `CONFIG`
  audit entry records the previous MOTD in full; a configuration file stating
  more is refused at start.
- **History pages in `(time, msgid)` order (migrations 0093 and 0094).** 0093
  builds its index concurrently, outside a transaction, so writers to
  `messages` are not blocked; on a large table it takes a while. A start
  interrupted during the build drops the invalid index it left and builds it
  again. Read markers kept under a correspondent's nick are moved to the
  identity key conversations use.

## Stop timeout

On SIGTERM the daemon stops accepting work. In edge mode it then hands its
clients over to the next core (DESIGN §19.3): each step of that cut waits at
most a fixed cap — up to 35 seconds for a rebuild still under way, 5 for
every edge to pause, 10 for the work in flight to settle and 2 to close what
did not, 5 to close the sessions no edge holds, 2 for the local bouncer
sessions to stop sending, 5 to cut the core shards, 5 for the local sessions'
records, 10 for every edge to take what is left and the cut, and 5 to record
the cut — and the whole cut is stopped at their sum, 84 seconds, after which
every session ends loudly instead. The daemon then tells every bouncer network's
upstream goodbye (`QUIT`, at most 15 seconds for all of them together, so the
next process to serve does not meet its session there still logged in),
drains its core shards for at most 5 seconds, lets every client connection
deliver its closing `ERROR` and close for at most 8 seconds, flushes buffered
writes to PostgreSQL for at most 30 seconds, and then gives the serving lease
back for at most 5 seconds, so a standby takes over at once. A process that is
killed instead says no goodbye: its upstream sessions end when the upstream
notices the dropped connection, and until then the next process to serve
finds its nick held there — it registers under the alternative nickname and
takes the configured one back once the ghost is gone or NickServ regains it. Give the container at least 150 seconds
before it is killed, as
`e6ircd.service` does: `stopTimeout: 150` (or more) in the ECS container
definition, `docker stop --time 150`, or `stop_grace_period: 150s` in Compose.
`tools/check-systemd-unit.sh` sums the cut's caps from the code with the other
steps, so this budget and the code cannot drift apart.
The Docker default of 10 seconds and the ECS default of 30 can both kill a
shutdown that was still flushing cleanly.

## High availability

One e6ircd process serves a database: it runs the IRC core, the bouncer
drivers (one upstream session per network), the database writer, storage
maintenance and sampling, and binds the IRC, attach and HTTP listeners. Any
other process started with the same configuration and database is a
**standby**. Two processes serving one database — the IRC equivalent of two
servers linked — is not supported: the lease makes it impossible.

- **Lease.** The serving process holds the one row of `serving_lease` and
  renews it every 3 seconds; the lease stands for 15 seconds after the last
  renewal, measured on PostgreSQL's clock (the hosts' clocks do not matter). A
  process that cannot confirm a renewal for 10 seconds — PostgreSQL is down,
  restarting or unreachable — is **fenced**: `/readyz` answers 503 with
  `"lease":"unconfirmed"`, it keeps every IRC connection and serves them from
  memory, and it keeps trying to renew. When PostgreSQL answers again and
  the lease is still its own (nobody took it, however long ago it expired),
  it resumes: `/readyz` answers 200 and it writes again. If another process
  took the lease meanwhile, it stops serving — the same bounded drain as
  SIGTERM, and a non-zero exit, so its service manager restarts it as a
  standby. So a PostgreSQL restart or outage on a single server no longer
  disconnects anyone. The cost, in a network split between two hosts: the
  clients still connected to the old holder stay on it, served from memory
  and without the database, until it reaches PostgreSQL again and sees the
  takeover; only then are they disconnected and reconnect to the new holder.
  Its bouncer networks stay connected meanwhile too, so the upstream may see
  a session from each holder until then. When a standby takes the lease it
  ends every PostgreSQL connection the previous holder opened, and a process
  without the lease cannot open a new one: nothing a stalled holder had in
  flight lands after the takeover. Every
  process must connect as the same database role, so the new holder can see
  and end the old one's connections. Each takeover is an audit entry
  (`SERVING_LEASE_ACQUIRE`); `e6irc_serving_lease_held` and
  `e6irc_serving_lease_epoch` are on the metrics.
- **Standby.** A standby says so on stderr (`standing by: the serving lease is
  held by ADDRESS pid PID, e6ircd VERSION ...`), binds only the HTTP address,
  and answers there `/healthz` 200 and `/readyz` 503 with
  `{"role":"standby","holder":...}`; everything else is 503. It takes over the
  moment the holder releases the lease (a graceful stop announces it) or 15
  seconds after the holder's last renewal (a crash), then closes that listener,
  migrates, and binds everything as a serving process does. A standby whose
  binary is older than the schema refuses to start: it could never serve.
- **Load balancer.** Route to the process whose `/readyz` answers 200: HTTP
  and WebSockets on the HTTP port, and TCP 6697 (IRC) and the attach port with
  that same HTTP check as their health check — a standby does not bind them.
- **Service manager.** Run the same unit (`e6ircd.service`) with the same
  configuration on two hosts; whichever starts first serves. `Restart=` brings
  a crashed process, or one that found its lease taken, back as the standby.
- **Rolling upgrade.** Restart the standby with the new release (a standby may
  be newer than the schema); send SIGTERM to the serving process — the
  upgraded standby takes over and migrates; then start the old serving host
  with the new release, as the standby. The first upgrade to a release with the
  lease is the exception above: stop every process.
- **Recovery point.** A graceful handoff loses nothing: the serving process
  flushes to PostgreSQL before it releases. After a crash the new process
  serves what PostgreSQL committed; lines the dead process had buffered and not
  yet written (at most one batch of the history writer, and a bouncer
  network's last backlog lines) are lost. Clients reconnect; bouncer networks
  are dialled again by the new holder.
- **PostgreSQL itself must fail over with synchronous replication**
  (`synchronous_commit = on` with a synchronous standby, or a managed service
  that promises no committed transaction is lost at failover). An asynchronous
  replica promoted after a crash can roll the lease row back to an earlier
  holder — and with it every write after that point — so two processes could
  each believe the lease theirs until the next renewal.

## Running on any container host

Any host that runs an OCI image can run e6irc. It has to provide:

- **The environment** in the table above. Three variables are required, and
  `E6IRC_SERVER_NAME` for the first start; secrets
  (`E6IRC_DATABASE_URL`, `E6IRC_SECRET_KEY`, `E6IRC_PREVIOUS_SECRET_KEYS`,
  `E6IRC_OIDC_CLIENT_SECRET`, `E6IRC_BOOTSTRAP_TOKEN`, `E6IRC_MONITORING_TOKEN`)
  belong in the host's secret store, not in the image
  or a committed file. A value with a pasted carriage return or newline is
  refused at start by variable name.
- **A persistent PostgreSQL** reachable from the container. Every durable
  thing — accounts, sessions, channel registrations, history, network
  definitions, sealed credentials, managed configuration, audit — lives there;
  the container itself keeps no state and needs no volume. Migrations run at
  start. If PostgreSQL is not accepting connections yet (still starting, or
  started after this container), the daemon retries the first connection for
  five minutes — doubling backoff capped at 30 s, one stderr line per attempt
  (`[database] startup_wait_seconds` in a configuration file) — and then
  exits non-zero. Migrations run on a connection of their own with no
  statement timeout, so a long one (an index on a table that has grown for
  months) completes; one that waits more than 10 s for a lock — another
  process migrating, a long transaction — is abandoned and retried, up to six
  attempts, one stderr line each. Only the process holding the serving lease
  migrates (see High availability). Back it up with `tools/backup-postgres.sh`.
- **The master key**, `E6IRC_SECRET_KEY`, kept outside the database and backed
  up separately. Without it the daemon cannot store upstream or managed
  credentials, and a database restored without it holds ciphertext nothing can
  open.
- **One published HTTP port**: the container listens on `0.0.0.0:8080`
  (`E6IRC_HTTP_ADDR`) for pages, the REST API, and both WebSockets (`/ws/ui`
  for the chat client, `/ws/irc` for IRC over WebSocket). Put TLS in front of
  it, let WebSocket upgrades through, and set `E6IRC_PUBLIC_URL` to the
  external HTTPS origin; session cookies are `Secure` unless
  `E6IRC_SECURE_COOKIES=false`. `GET /healthz` is the liveness probe: 200
  while the process answers and every core shard has finished an event
  within 45 seconds, 503 when one is wedged, and never a database check, so a
  database outage shows on `GET /readyz` (core and database readiness)
  rather than restart-looping the container. The image contains no
  HTTP client, so its `HEALTHCHECK` is the daemon probing itself: `e6ircd
  healthcheck [--ready] [--addr ip:port]` reads the same `E6IRC_HTTP_ADDR` the
  server binds (no configuration file needed), exits 0 only on HTTP 200,
  and finishes within three seconds. `/healthz` is bound once startup has
  reached PostgreSQL, migrated, and loaded its state, so the image's
  `HEALTHCHECK` start period (420 s) outlasts the default 300 s database wait
  plus the migration lock retries; an orchestrator's own liveness probe needs
  the same initial delay (or a startup probe). A host that prefers its own probe can
  still use the two endpoints directly. The probes bypass the service's
  admission bounds, so they answer while it is saturated: one client address
  may hold 128 connections (a trusted proxy is exempt; its clients are
  counted by forwarded address instead) and 32 requests in flight (more are
  answered `429`), a request's headers must arrive within 10 seconds, and a
  kept-alive connection idle for 10 seconds is closed.
- **No published IRC port.** The raw IRC listener defaults to loopback
  (`127.0.0.1:6667`) and is not meant to be exposed from this image, which
  renders no TLS listener; IRC clients reach the server over `/ws/irc`. The
  optional BNC listener an administrator can enable in the console is a TCP
  port of its own, needs a host that can publish one, and off loopback needs a
  certificate the container can read ([BNC attach listener](#bnc-attach-listener)).
- **A stop timeout of at least 150 seconds** ([Stop timeout](#stop-timeout)).
- **Outbound network access** to PostgreSQL, to the OpenID Connect issuer, and
  — for always-on networks and bridges — to the IRC networks (TCP 6697 for the
  curated ones), Matrix homeservers, Discord, and Slack. On an account's
  behalf the daemon will not dial a link-local address (which includes the
  cloud metadata endpoint `169.254.169.254`), nor an unspecified, multicast,
  broadcast, or documentation address; it checks every address a hostname
  resolves to at dial time. Loopback, RFC 1918, carrier-grade NAT and
  unique-local addresses are refused too, by default and at dial time; only a
  configuration file's `internal_upstreams = "allow"` (meant for test
  harnesses) admits them, and the container exposes no variable for it.

### Egress and public IRC networks

Public IRC networks judge a connection by the address it comes from, so whether
an always-on network connects depends on the host's egress, not on e6irc. The
recorded case: on 2026-08-23 a production container on a cloud host registered
and joined its configured channels on OFTC and Ergo Testnet, while Libera
refused the same container's IPv4 address unless the connection authenticated
with an existing, email-verified NickServ account over SASL — and that
container had no routable IPv6 to try instead. A 2026-09-20 run from a
residential address reached Libera without SASL. Evidence from one egress
qualifies only that egress.

When a network refuses registration, the driver retries on its refusal schedule
(30 seconds, then 1, 2, and 4 minutes). A refusal that is the network's policy
— Libera's "SASL access only", a throttle, a ban — is then retried every 4
minutes for as long as it lasts and never parks; one that may be a
configuration fault, such as a nickname the network will not take, parks on the
fifth in a row (DESIGN §10.3 has the three policies). The network's row in the
chat client says so and quotes the network's own words ("The network said: …"),
and the repair is in that network's settings: enter the NickServ account and
password there, and the driver reconnects with SASL. A host without IPv6 egress
simply has one address family fewer to be judged by; give the container
routable IPv6 where the host offers it.

A network configured with a SASL account whose server offers no SASL at all
(OFTC) is retried for about an hour and then parks (`sasl_unavailable`); one
whose server offers SASL but none of the mechanisms a password can use parks at
once (`sasl_mechanism_unavailable`). Either way the repair is to remove the SASL
account and sign in with a client certificate instead.

### Client certificates and remembered channels

A network an account adds signs in with a client certificate made on its
console page. A network in the configuration file names one as two PEM files on
this host, and must use TLS:

```toml
[[network]]
kind = "irc"
name = "oftc"
owner = "alice"
addr = "irc.oftc.net:6697"
tls = true
nick = "alice"
username = "alice"
realname = "Alice"
autojoin = ["#oftc"]
buffer_cap = 1000
client_certificate = { certificate = "/etc/e6irc/oftc-cert.pem", key = "/etc/e6irc/oftc-key.pem" }
```

The files are read when the network starts, and again when the owner's
reactivation restarts it; a key that does not belong to the certificate, or a
file that cannot be read, fails the start and names the file. Keep the key
readable by the service user alone (mode 0600). To rotate it, replace both
files and restart. The certificate's SHA-256 and SHA-512 fingerprints are shown
on the network's console pages; register one with the network's services
(`/msg NickServ CERT ADD`). The daemon presents the certificate over TLS and
logs in with SASL EXTERNAL where the network offers it, and otherwise presents
the certificate alone, which NickServ's CertFP recognises.

Every IRC network, configured or added by an account, remembers the channels
its session is confirmed in and rejoins them after a restart. The channels are
stored in PostgreSQL, along with the keys they were joined with, sealed with
the master key. A configured network's channels are stored by its owner and
name; a start deletes the rows of networks the configuration no longer defines.

## SSO endpoints (served by e6ircd)

- `GET /api/v1/auth/oidc/shauth/start` — interactive login
- `GET /api/v1/auth/oidc/shauth/sso` — silent `prompt=none` session probe
- `GET /api/v1/auth/oidc/shauth/callback` — registered authorization callback
- `POST /api/v1/auth/logout` — RP-initiated logout (ends the Shauth session too); the sign-out control is a form post carrying the session's CSRF value in its body
- `GET /healthz` — liveness: process up and every core shard fresh (Shauth catalog health URL)

The Shauth client registered `E6IRC_PUBLIC_URL` as its post-logout return and
`${E6IRC_PUBLIC_URL}/api/v1/auth/oidc/shauth/callback` as its authorization
callback. Opening the application root directly or through the Shauth catalog
used the same fail-closed silent-SSO entry flow.
