# syntax=docker/dockerfile:1
# e6irc server image. The daemon reads its configuration from the environment
# itself (`--config-from-environment`; the deployment injects DATABASE_URL and
# the Shauth OIDC client secret from AWS Secrets Manager), in memory, so the
# runtime image is distroless: no shell, no package manager, no script, and no
# secrets-bearing file. The frontend is built and embedded in the server
# binary, so startup performs no build work and the authenticated application
# entry point is always served by this image.
#
# Every base image is pinned by index digest, so a rebuild of one commit uses
# the same compiler and the same runtime libraries as the build CI verified;
# a tag alone moves. To refresh one, resolve its tag again with
# `docker buildx imagetools inspect IMAGE:TAG` and update the digest and the
# date beside it in the same change.
#   node:24-bookworm-slim resolved 2026-08-09
#   rust:1-bookworm       resolved 2026-09-20 (Rust 1.98.1)
#   gcr.io/distroless/cc-debian12:nonroot resolved 2026-09-20
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
# repository state into the runtime stage. It has no default: an image whose
# revision label says "unknown" is not provenance, so a build without
# `--build-arg E6IRC_BUILD_REVISION=$(git rev-parse HEAD)` stops here.
ARG E6IRC_BUILD_REVISION
RUN test -n "$E6IRC_BUILD_REVISION" || { echo "E6IRC_BUILD_REVISION build argument is required" >&2; exit 1; }
ENV E6IRC_BUILD_REVISION=$E6IRC_BUILD_REVISION
COPY . .
COPY --from=web-build /src/web/dist ./web/dist
RUN cargo build --release -p e6ircd --all-features

# glibc, libgcc and CA certificates, and nothing else: the release binary is
# dynamically linked against the same Debian 12 glibc the build stage has.
# (`scratch` would need a static musl build, whose allocator costs a threaded
# server more than the few megabytes it saves.)
FROM gcr.io/distroless/cc-debian12:nonroot@sha256:9dac0a79194e45a7da0158a9c6da57b217585af0786db3845d1f0ec1a0dd182f
COPY --from=build /src/target/release/e6ircd /usr/local/bin/e6ircd
# Numeric, and the one earlier images ran as: a deployment's security context
# that names the user keeps working, and no passwd entry is needed for it.
USER 10001:10001
EXPOSE 8080
# The image has no HTTP client, so the daemon probes itself: `e6ircd
# healthcheck` reads the same E6IRC_HTTP_ADDR the server binds and needs no
# configuration file. The start period covers migrations on a cold database.
HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
  CMD ["/usr/local/bin/e6ircd", "healthcheck"]
ENTRYPOINT ["/usr/local/bin/e6ircd"]
# Replace the command with `--config /path/to/e6irc.toml` to run from a
# mounted configuration file instead; then also set E6IRC_HTTP_ADDR to the
# file's [http].addr (or override the health check with
# `e6ircd healthcheck --addr ip:port`), because the probe reads the environment,
# not the file.
CMD ["--config-from-environment"]
