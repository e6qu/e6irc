#!/usr/bin/env bash
# Boot the built production image the way a container host does: its real
# entrypoint reading the container's environment, its unprivileged user, its
# dynamic libraries (the runtime stage is distroless, so a library the binary
# needs and the base lacks shows up here and nowhere else), and a PostgreSQL it
# reaches over a network. Inspecting the image's files proves none of that.
# Portable to bash 3.2.
#
#   tools/test-production-container.sh IMAGE
set -euo pipefail

[ "$#" -eq 1 ] || { echo "usage: $0 IMAGE" >&2; exit 2; }
image=$1
suffix="$$-$(date +%s)"
network="e6irc-image-test-$suffix"
database="e6irc-image-test-pg-$suffix"
server="e6irc-image-test-$suffix"
# The same digest ci.yml pins its PostgreSQL service to.
postgres_image="${E6IRC_TEST_POSTGRES_IMAGE:-postgres:18-alpine@sha256:77f585114c32fbca283dc835b0596f4e52b51b4c6662d7810b2f4084f60a1873}"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    echo "--- $server log" >&2
    docker logs "$server" >&2 2>&1 || true
  fi
  docker rm --force "$server" "$database" >/dev/null 2>&1 || true
  docker network rm "$network" >/dev/null 2>&1 || true
  exit "$status"
}
trap cleanup EXIT

docker network create "$network" >/dev/null
docker run --detach --name "$database" --network "$network" \
  --env POSTGRES_PASSWORD=image-test --env POSTGRES_DB=e6irc \
  "$postgres_image" >/dev/null
deadline=$((SECONDS + 60))
until docker exec "$database" pg_isready --quiet --username postgres --dbname e6irc; do
  [ "$SECONDS" -lt "$deadline" ] || { echo "PostgreSQL did not become ready" >&2; exit 1; }
  sleep 1
done

docker run --detach --name "$server" --network "$network" \
  --publish 127.0.0.1::8080 \
  --env E6IRC_SERVER_NAME=irc.image.test \
  --env E6IRC_PUBLIC_URL=http://127.0.0.1:8080 \
  --env E6IRC_SECURE_COOKIES=false \
  --env E6IRC_DATABASE_URL="postgres://postgres:image-test@$database:5432/e6irc" \
  --env APPLICATION_RELEASE_REVISION=0123456789ab \
  "$image" >/dev/null
origin="http://$(docker port "$server" 8080/tcp | head -n 1)"

# `docker port` answers before the daemon listens: it still has to read and
# validate its configuration and migrate the database.
deadline=$((SECONDS + 90))
until [ "$(curl --silent --output /dev/null --write-out '%{http_code}' "$origin/healthz")" = 200 ]; do
  if [ "$(docker inspect --format '{{.State.Running}}' "$server")" != true ]; then
    echo "the container exited before it became healthy" >&2
    exit 1
  fi
  [ "$SECONDS" -lt "$deadline" ] || { echo "the container did not become healthy" >&2; exit 1; }
  sleep 1
done
curl --silent --fail "$origin/readyz" | grep -F '"database":"ready"' >/dev/null || {
  echo "/readyz does not report a ready database:" >&2
  curl --silent "$origin/readyz" >&2 || true
  exit 1
}
curl --silent --fail "$origin/login" | grep -F '<form' >/dev/null || {
  echo "the image did not serve its login page" >&2
  exit 1
}

# The image's own probe, run the way the container runtime runs it: inside the
# container, with only the container's environment. It must agree with what
# the host just saw, fail for a port nothing listens on, and refuse bad usage.
docker exec "$server" /usr/local/bin/e6ircd healthcheck || {
  echo "the image's healthcheck failed against a server the host can reach" >&2
  exit 1
}
docker exec "$server" /usr/local/bin/e6ircd healthcheck --ready || {
  echo "the image's readiness probe failed although /readyz reports ready" >&2
  exit 1
}
if docker exec "$server" /usr/local/bin/e6ircd healthcheck --addr 127.0.0.1:9 2>/dev/null; then
  echo "the image's healthcheck passed for a port nothing listens on" >&2
  exit 1
fi
declared="$(docker inspect --format '{{json .Config.Healthcheck.Test}}' "$server")"
case "$declared" in
  *'"healthcheck"'*) ;;
  *) echo "the image declares no HEALTHCHECK: $declared" >&2; exit 1 ;;
esac

# The image has no `id` to ask, so the declared user is read from the image and
# a root process is ruled out by what the daemon could not have done otherwise:
# nothing. What is checked is that there is no shell to be root in.
user="$(docker inspect --format '{{.Config.User}}' "$server")"
[ "$user" = 10001:10001 ] || { echo "the image runs as '$user', expected 10001:10001" >&2; exit 1; }
for shell in /bin/sh /bin/bash /busybox/sh; do
  if docker exec "$server" "$shell" -c true >/dev/null 2>&1; then
    echo "the image has a shell at $shell; the runtime stage must be distroless" >&2
    exit 1
  fi
done

# A missing setting is refused by name before anything listens, and the refusal
# does not print the settings that were given.
if refusal="$(docker run --rm --network "$network" \
  --env E6IRC_SERVER_NAME=irc.image.test \
  --env E6IRC_PUBLIC_URL=http://127.0.0.1:8080 \
  --env E6IRC_DATABASE_URL="postgres://postgres:image-test@$database:5432/e6irc" \
  "$image" 2>&1)"; then
  echo "the image started without APPLICATION_RELEASE_REVISION" >&2
  exit 1
fi
case "$refusal" in
  *image-test*) echo "the refusal printed the database URL: $refusal" >&2; exit 1 ;;
  *'APPLICATION_RELEASE_REVISION is required'*) ;;
  *) echo "the refusal does not name the missing variable: $refusal" >&2; exit 1 ;;
esac

# SIGTERM with the documented stop budget must end in a clean exit, not a kill.
docker stop --time 55 "$server" >/dev/null
exit_code="$(docker inspect --format '{{.State.ExitCode}}' "$server")"
[ "$exit_code" = 0 ] || { echo "graceful stop exited $exit_code" >&2; exit 1; }
echo "production container contract ok"
