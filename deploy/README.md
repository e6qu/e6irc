# Deploying e6irc

The dev environment in `github.com/e6qu/infra` runs e6irc as an ARM64 Amazon
ECS Fargate service on the shared VPC/cluster, behind API Gateway at
`https://e6irc.dev.e6qu.dev`, with a per-tenant database on the shared
PostgreSQL (`fck-rds`) and Shauth as its OpenID Connect SSO source.

## Image

`Dockerfile` builds the Vite frontend and embeds it into `e6ircd` before
copying the complete server onto a slim Debian base. No build tool or startup
build step exists in the runtime image. The `.github/workflows/release.yml`
workflow publishes `ghcr.io/e6qu/e6irc:<short-sha>` plus the direct
`<short-sha>-amd64` and `<short-sha>-arm64` images on every push to `main`.
It publishes no mutable branch or `latest` tag and retains the newest 20
release groups, including their untagged provenance/SBOM referrers.

Each architecture digest carries signed GitHub build provenance and an SPDX
software bill of materials as OCI referrers; the assembled commit-SHA manifest
carries signed assembly provenance. Verify them after authenticating `gh` for
the repository:

```sh
gh attestation verify oci://ghcr.io/e6qu/e6irc:<short-sha> -R e6qu/e6irc
gh attestation verify oci://ghcr.io/e6qu/e6irc:<short-sha>-amd64 \
  -R e6qu/e6irc --predicate-type https://spdx.dev/Document/v2.3
```

## Native archives

A Git tag exactly matching `v<workspace-version>` publishes deterministic
archives for Linux, macOS, and Windows on x86-64 and ARM64. Every archive
contains the daemon, CLI, TUI, README, license, and systemd unit. Download the
archive for the host together with `SHA256SUMS`, then verify both transport
integrity and GitHub build provenance:

```sh
grep 'e6irc-0.1.0-x86_64-unknown-linux-gnu.tar.gz$' SHA256SUMS \
  | sha256sum --check
gh attestation verify e6irc-0.1.0-x86_64-unknown-linux-gnu.tar.gz \
  -R e6qu/e6irc
```

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

The unit uses SIGTERM and a 35-second stop budget, exceeding the daemon’s
30-second bounded PostgreSQL flush budget so systemd cannot kill a still-clean
shutdown first. It grants no ambient capabilities and makes the host filesystem
read-only to the process; listeners on privileged ports therefore need a
reverse proxy or an explicit, reviewed service override.

## Bootstrap configuration (env → TOML)

`e6ircd` reads a TOML config file. `deploy/docker-entrypoint.sh` renders that
file from environment at container start (the deployment injects secrets —
`E6IRC_DATABASE_URL`, `E6IRC_OIDC_CLIENT_SECRET` — from AWS Secrets Manager)
and then execs the server. The generated file has mode `0600`; when no explicit
path is supplied its name is unpredictable. Missing required values fail the
container loudly rather than starting half-configured. On the first database-backed start,
operational values are imported into the revisioned `server_settings` row.
After that, administrators manage them at `/console/configuration`; the
database URL, secrets-key source, HTTP bind, immutable release revision, and
optional static administrator grants or the one-time first-administrator token
stay in bootstrap because the console depends on them. On an empty account
store, set `E6IRC_BOOTSTRAP_TOKEN`, open `/bootstrap`, and create the first
durable administrator. The route closes permanently as soon as any account
exists; remove the environment secret after successful initialization.
The same page owns live history and audit retention (30 and 365 days by
default). A supervised worker applies those limits in bounded batches and also
removes expired browser sessions, personal access tokens, device grants, and
consumed logout tokens; operators should alert on its fixed-category database
errors rather than scheduling a second cleanup job.

Deployments that still carry plaintext OIDC/operator credentials need a master
key before the console can own those secrets. Until then, bootstrap credentials
remain authoritative and the UI labels them accordingly. Once a key is
configured, the next start seals and imports them atomically.

| Variable | Required | Meaning |
|---|---|---|
| `E6IRC_SERVER_NAME` | yes | IRC server name, e.g. `e6irc.dev.e6qu.dev` |
| `E6IRC_PUBLIC_URL` | yes | External base URL; OIDC redirect + post-logout base |
| `E6IRC_DATABASE_URL` | yes (secret) | PostgreSQL URL (`fck-rds` tenant) |
| `E6IRC_SECRET_KEY` | for credential storage (secret) | Base64 32-byte primary key; new managed and account-network credentials are sealed with it |
| `E6IRC_PREVIOUS_SECRET_KEYS` | only during rotation (secret) | Comma-separated old keys accepted for reads until `e6ircd rotate-secrets` commits |
| `E6IRC_NETWORK_NAME` | no (`e6qu`) | IRC network name |
| `E6IRC_HTTP_ADDR` | no (`0.0.0.0:8080`) | HTTP/REST/WebSocket listen address |
| `E6IRC_IRC_ADDR` | no (`127.0.0.1:6667`) | Raw IRC listener — loopback only; IRC is reached over WebSocket (`/ws/irc`) publicly |
| `E6IRC_SECURE_COOKIES` | no (`true`) | Mark session cookies `Secure` |
| `E6IRC_ADMIN_ACCOUNTS` | no | Comma-separated admin account names |
| `E6IRC_BOOTSTRAP_TOKEN` | no (secret; 32–512 bytes) | One-time browser token for creating the first durable administrator on an empty account store |
| `E6IRC_OIDC_ISSUER` | no | Shauth issuer, e.g. `https://auth.dev.e6qu.dev` (enables SSO) |
| `E6IRC_OIDC_CLIENT_ID` | with issuer | Shauth OIDC client id, e.g. `e6irc-dev` |
| `E6IRC_OIDC_CLIENT_SECRET` | with issuer (secret) | Shauth OIDC client secret |
| `E6IRC_OIDC_NAME` | no (`shauth`) | Provider name (URL segment) |
| `E6IRC_OIDC_END_SESSION` | with issuer | RP-initiated logout endpoint, e.g. `https://auth.dev.e6qu.dev/oauth2/sessions/logout` |

### Rotate the credential key

Install a newly generated key as `E6IRC_SECRET_KEY`, retain the old value in
`E6IRC_PREVIOUS_SECRET_KEYS`, and restart the service. The new process can read
both generations but writes only with the new primary. With the same
environment and generated config, run:

```sh
e6ircd rotate-secrets --config "$E6IRC_CONFIG_PATH"
```

The command re-seals managed configuration and every account-network
credential in one PostgreSQL transaction and writes a redacted audit record.
It exits nonzero and rolls the whole transaction back if any value cannot be
proven readable. After success, remove `E6IRC_PREVIOUS_SECRET_KEYS` and restart.

## SSO endpoints (served by e6ircd)

- `GET /api/v1/auth/oidc/shauth/start` — interactive login
- `GET /api/v1/auth/oidc/shauth/sso` — silent `prompt=none` session probe
- `GET /api/v1/auth/oidc/shauth/callback` — registered authorization callback
- `GET /api/v1/auth/logout` — RP-initiated logout (ends the Shauth session too)
- `GET /healthz` — liveness (Shauth catalog health URL)

The Shauth client registered `E6IRC_PUBLIC_URL` as its post-logout return and
`${E6IRC_PUBLIC_URL}/api/v1/auth/oidc/shauth/callback` as its authorization
callback. Opening the application root directly or through the Shauth catalog
used the same fail-closed silent-SSO entry flow.
