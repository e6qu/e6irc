# syntax=docker/dockerfile:1
# e6irc server image. Config is rendered at start from environment by
# deploy/docker-entrypoint.sh (the deployment injects DATABASE_URL and the
# Shauth OIDC client secret from AWS Secrets Manager). Built without the
# embed-web feature: the REST API, WebSocket, and SSO endpoints are served
# directly; web assets, when present, are hosted separately.
FROM rust:1-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --release -p e6ircd

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
