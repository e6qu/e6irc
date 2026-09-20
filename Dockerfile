# syntax=docker/dockerfile:1
# e6irc server image. Config is rendered at start from environment by
# deploy/docker-entrypoint.sh (the deployment injects DATABASE_URL and the
# Shauth OIDC client secret from AWS Secrets Manager). The frontend is built
# and embedded in the server binary, so startup performs no build work and
# the authenticated application entry point is always served by this image.
#
# Every base image is pinned by index digest, so a rebuild of one commit uses
# the same compiler and the same runtime libraries as the build CI verified;
# a tag alone moves. To refresh one, resolve its tag again with
# `docker buildx imagetools inspect IMAGE:TAG` and update the digest and the
# date beside it in the same change.
#   node:24-bookworm-slim resolved 2026-08-09
#   rust:1-bookworm       resolved 2026-09-20 (Rust 1.98.1)
#   debian:bookworm-slim  resolved 2026-09-20
FROM node:24-bookworm-slim@sha256:6f7b03f7c2c8e2e784dcf9295400527b9b1270fd37b7e9a7285cf83b6951452d AS web-build
WORKDIR /src/web
RUN npm install --global pnpm@11.15.1
COPY web/package.json web/pnpm-lock.yaml ./
RUN pnpm install --frozen-lockfile
COPY web/ ./
RUN pnpm build

FROM rust:1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build
WORKDIR /src
# The running binary reports this as e6irc_build_info's revision label; the
# build arg keeps the image's provenance honest without baking the whole
# repository state into the runtime stage.
ARG E6IRC_BUILD_REVISION=unknown
ENV E6IRC_BUILD_REVISION=$E6IRC_BUILD_REVISION
COPY . .
COPY --from=web-build /src/web/dist ./web/dist
RUN cargo build --release -p e6ircd --all-features

FROM debian:bookworm-slim@sha256:3783cc01769c7b2b1b83a5c5ad96c815348e28ed7da68e2e3687004faa906251
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
