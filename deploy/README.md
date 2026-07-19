# Deploying e6irc

The dev environment in `github.com/e6qu/infra` runs e6irc as an ARM64 Amazon
ECS Fargate service on the shared VPC/cluster, behind API Gateway at
`https://e6irc.dev.e6qu.dev`, with a per-tenant database on the shared
PostgreSQL (`fck-rds`) and Shauth as its OpenID Connect SSO source.

## Image

`Dockerfile` builds `e6ircd` (without the `embed-web` feature) onto a slim
Debian base. The `.github/workflows/release.yml` workflow publishes a
multi-arch image to `ghcr.io/e6qu/e6irc` on every push to `main`; infra pins
an immutable digest.

## Runtime configuration (env → TOML)

`e6ircd` reads a TOML config file. `deploy/docker-entrypoint.sh` renders that
file from environment at container start (the deployment injects secrets —
`E6IRC_DATABASE_URL`, `E6IRC_OIDC_CLIENT_SECRET` — from AWS Secrets Manager)
and then execs the server. Missing required values fail the container loudly
rather than starting half-configured.

| Variable | Required | Meaning |
|---|---|---|
| `E6IRC_SERVER_NAME` | yes | IRC server name, e.g. `e6irc.dev.e6qu.dev` |
| `E6IRC_PUBLIC_URL` | yes | External base URL; OIDC redirect + post-logout base |
| `E6IRC_DATABASE_URL` | yes (secret) | PostgreSQL URL (`fck-rds` tenant) |
| `E6IRC_NETWORK_NAME` | no (`e6qu`) | IRC network name |
| `E6IRC_HTTP_ADDR` | no (`0.0.0.0:8080`) | HTTP/REST/WebSocket listen address |
| `E6IRC_IRC_ADDR` | no (`127.0.0.1:6667`) | Raw IRC listener — loopback only; IRC is reached over WebSocket (`/ws`) publicly |
| `E6IRC_SECURE_COOKIES` | no (`true`) | Mark session cookies `Secure` |
| `E6IRC_ADMIN_ACCOUNTS` | no | Comma-separated admin account names |
| `E6IRC_OIDC_ISSUER` | no | Shauth issuer, e.g. `https://auth.dev.e6qu.dev` (enables SSO) |
| `E6IRC_OIDC_CLIENT_ID` | with issuer | Shauth OIDC client id, e.g. `e6irc-dev` |
| `E6IRC_OIDC_CLIENT_SECRET` | with issuer (secret) | Shauth OIDC client secret |
| `E6IRC_OIDC_NAME` | no (`shauth`) | Provider name (URL segment) |
| `E6IRC_OIDC_END_SESSION` | no | RP-initiated logout endpoint, e.g. `https://auth.dev.e6qu.dev/oauth2/sessions/logout` |

## SSO endpoints (served by e6ircd)

- `GET /api/v1/auth/oidc/shauth/start` — interactive login
- `GET /api/v1/auth/oidc/shauth/sso` — silent `prompt=none` session probe
- `GET /api/v1/auth/logout` — RP-initiated logout (ends the Shauth session too)
- `GET /healthz` — liveness (Shauth catalog health URL)
