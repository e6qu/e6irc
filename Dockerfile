# syntax=docker/dockerfile:1
# e6irc server image. Config is rendered at start from environment by
# deploy/docker-entrypoint.sh (the deployment injects DATABASE_URL and the
# Shauth OIDC client secret from AWS Secrets Manager). The frontend is built
# and embedded in the server binary, so startup performs no build work and
# the authenticated application entry point is always served by this image.
FROM node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS web-build
WORKDIR /src/web
RUN npm install --global pnpm@11.15.1
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
COPY --from=web-build /src/web/dist ./web/dist
RUN cargo build --release -p e6ircd --features embed-web

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/* \
 && useradd -r -u 10001 e6irc
COPY --from=build /src/target/release/e6ircd /usr/local/bin/e6ircd
COPY deploy/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh
USER e6irc
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
