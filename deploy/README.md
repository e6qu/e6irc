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
release groups.

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
| `E6IRC_IRC_ADDR` | no (`127.0.0.1:6667`) | Raw IRC listener — loopback only; IRC is reached over WebSocket (`/ws/irc`) publicly |
| `E6IRC_SECURE_COOKIES` | no (`true`) | Mark session cookies `Secure` |
| `E6IRC_ADMIN_ACCOUNTS` | no | Comma-separated admin account names |
| `E6IRC_OIDC_ISSUER` | no | Shauth issuer, e.g. `https://auth.dev.e6qu.dev` (enables SSO) |
| `E6IRC_OIDC_CLIENT_ID` | with issuer | Shauth OIDC client id, e.g. `e6irc-dev` |
| `E6IRC_OIDC_CLIENT_SECRET` | with issuer (secret) | Shauth OIDC client secret |
| `E6IRC_OIDC_NAME` | no (`shauth`) | Provider name (URL segment) |
| `E6IRC_OIDC_END_SESSION` | with issuer | RP-initiated logout endpoint, e.g. `https://auth.dev.e6qu.dev/oauth2/sessions/logout` |

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
