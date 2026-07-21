#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-or-later
set -euo pipefail

: "${SHAUTH_SOURCE_DIR:?SHAUTH_SOURCE_DIR must point to the exact Shauth checkout}"

readonly expected_shauth_commit="0fda680cba964e5768ed75a9c3e5b7230c418ca6"
actual_shauth_commit="$(git -C "$SHAUTH_SOURCE_DIR" rev-parse HEAD)"
if [[ "$actual_shauth_commit" != "$expected_shauth_commit" ]]; then
  echo "Shauth checkout is $actual_shauth_commit; expected $expected_shauth_commit" >&2
  exit 1
fi
if [[ -n "$(git -C "$SHAUTH_SOURCE_DIR" status --porcelain)" ]]; then
  echo "Shauth checkout must be clean at $expected_shauth_commit" >&2
  exit 1
fi

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
primary_port="${E6IRC_SSO_PRIMARY_PORT:-18083}"
secondary_port="${E6IRC_SSO_SECONDARY_PORT:-18084}"
case "$primary_port:$secondary_port" in
  *[!0-9:]* | :*) echo "e6irc SSO ports must be numeric" >&2; exit 2 ;;
esac
if [[ "$primary_port" == "$secondary_port" ]]; then
  echo "e6irc SSO ports must be distinct" >&2
  exit 2
fi
export E6IRC_SSO_PRIMARY_PORT="$primary_port"
export E6IRC_SSO_SECONDARY_PORT="$secondary_port"

compose=(docker compose --project-directory "$SHAUTH_SOURCE_DIR" -f "$SHAUTH_SOURCE_DIR/compose.yaml" -f "$root/test/shauth/compose.override.yaml" -p e6irc-shauth-sso)
temporary="$(mktemp -d)"
primary_pid=""
secondary_pid=""

random_secret() {
  openssl rand -base64 48 | tr -d '\n'
}

cleanup() {
  status=$?
  for pid in "$primary_pid" "$secondary_pid"; do
    [[ -n "$pid" ]] || continue
    kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "$primary_pid" "$secondary_pid"; do
    [[ -n "$pid" ]] || continue
    wait "$pid" >/dev/null 2>&1 || true
  done
  if [[ "$status" -ne 0 ]]; then
    "${compose[@]}" logs --no-color --tail=180 shauth hydra postgres >&2 || true
    for log in "$temporary"/*.log; do
      [[ -f "$log" ]] || continue
      printf '\n===== %s =====\n' "$log" >&2
      tail -180 "$log" >&2 || true
    done
  fi
  "${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf "$temporary"
  return "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

POSTGRES_PASSWORD="$(openssl rand -hex 32)"
export POSTGRES_PASSWORD
HYDRA_SYSTEM_SECRET="$(random_secret)"
export HYDRA_SYSTEM_SECRET
export HYDRA_DSN="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/hydra?sslmode=disable"
# Shauth reverse-proxies /.well-known, /oauth2 and /userinfo to Ory Hydra, so
# Hydra's issuer must be the origin relying parties actually reach. Advertising
# Hydra's own container port here would serve a discovery document whose issuer
# disagrees with the URL it was fetched from, which a conforming relying party
# rejects. This mirrors the deployed topology, where one public origin fronts
# both.
export HYDRA_PUBLIC_URL="http://localhost:8080"
export SHAUTH_PUBLIC_URL="http://localhost:8080"
export SHAUTH_DATABASE_URL="postgres://shauth:${POSTGRES_PASSWORD}@postgres:5432/shauth?sslmode=disable"
export GITHUB_CLIENT_ID="local-password-integration"
export GITHUB_CLIENT_SECRET="local-password-integration"
SHAUTH_BOOTSTRAP_ADMIN_PASSWORD="$(random_secret)"
export SHAUTH_BOOTSTRAP_ADMIN_PASSWORD
SHAUTH_VALIDATOR_TOKEN="$(random_secret)"
SHAUTH_VALIDATION_STATUS_TOKEN="$(random_secret)"
if [[ "$SHAUTH_VALIDATOR_TOKEN" == "$SHAUTH_VALIDATION_STATUS_TOKEN" ]]; then
  echo "Shauth validator and validation-status tokens must differ" >&2
  exit 1
fi
export SHAUTH_VALIDATOR_TOKEN SHAUTH_VALIDATION_STATUS_TOKEN
E6IRC_NON_AUTHENTIC_CREDENTIAL_SENTINEL="$(random_secret)"
if [[ "$E6IRC_NON_AUTHENTIC_CREDENTIAL_SENTINEL" == "$SHAUTH_BOOTSTRAP_ADMIN_PASSWORD" ]]; then
  echo "e6irc negative-probe sentinel must differ from the Shauth password" >&2
  exit 1
fi
export E6IRC_NON_AUTHENTIC_CREDENTIAL_SENTINEL
primary_secret="$(random_secret)"
secondary_secret="$(random_secret)"
E6IRC_TEST_REVISION="sha256:$({
  git -C "$root" rev-parse HEAD
  git -C "$root" diff --binary --no-ext-diff HEAD
} | openssl dgst -sha256 | awk '{print $NF}')"
export E6IRC_TEST_REVISION
primary_origin="http://e6irc-primary.localhost:$primary_port"
secondary_origin="http://e6irc-secondary.localhost:$secondary_port"
export SHAUTH_BOOTSTRAP_APPS_JSON
SHAUTH_BOOTSTRAP_APPS_JSON="$(jq -cn \
  --arg primary_origin "$primary_origin" \
  --arg primary_secret "$primary_secret" \
  --arg secondary_origin "$secondary_origin" \
  --arg secondary_secret "$secondary_secret" \
  --arg revision "$E6IRC_TEST_REVISION" '
  def app($slug; $name; $description; $origin; $secret): {
    slug: $slug,
    name: $name,
    description: $description,
    launch_url: ($origin + "/"),
    oidc_client_id: $slug,
    oidc_client_secret: $secret,
    redirect_uris: [($origin + "/api/v1/auth/oidc/shauth/callback")],
    post_logout_redirect_uris: [($origin + "/auth/shauth/logout/complete")],
    frontchannel_logout_uri: ($origin + "/api/v1/auth/oidc/frontchannel-logout"),
    backchannel_logout_uri: ($origin + "/api/v1/auth/oidc/backchannel-logout"),
    health_url: ($origin + "/healthz"),
    monitoring_url: "",
    validation_url: ($origin + "/auth/validation"),
    signed_out_url: ($origin + "/auth/signed-out"),
    release_revision: $revision
  };
  [
    app("e6irc-primary"; "e6irc primary"; "Primary e6irc SSO acceptance application."; $primary_origin; $primary_secret),
    app("e6irc-secondary"; "e6irc secondary"; "Witness e6irc SSO acceptance application."; $secondary_origin; $secondary_secret)
  ]')"

"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
"${compose[@]}" up --build --detach

for _ in $(seq 1 180); do
  if curl --fail --silent http://localhost:8080/healthz >/dev/null 2>&1 &&
    curl --fail --silent http://localhost:4444/health/ready >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
curl --fail --silent --show-error http://localhost:8080/healthz >/dev/null
curl --fail --silent --show-error http://localhost:4444/health/ready >/dev/null

"${compose[@]}" exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 \
  -c 'CREATE DATABASE e6irc_primary' >/dev/null
"${compose[@]}" exec -T postgres psql -U shauth -d shauth -v ON_ERROR_STOP=1 \
  -c 'CREATE DATABASE e6irc_secondary' >/dev/null

write_config() {
  config_path="$1"
  port="$2"
  origin="$3"
  database="$4"
  client_id="$5"
  client_secret="$6"
  cat >"$config_path" <<EOF
server_name = "irc.${client_id}.test"
network_name = "e6irc-sso-acceptance"
application_release_revision = "$E6IRC_TEST_REVISION"

[[listeners]]
addr = "127.0.0.1:0"

[http]
addr = "0.0.0.0:${port}"
public_url = "${origin}"
secure_cookies = false

[database]
url = "postgres://shauth:${POSTGRES_PASSWORD}@127.0.0.1:55432/${database}?sslmode=disable"

[[oidc]]
name = "shauth"
issuer_url = "http://localhost:8080"
client_id = "${client_id}"
client_secret = "${client_secret}"
scopes = ["profile", "email", "offline_access"]
# Shauth registers every managed application with client_secret_post, so the
# client must authenticate that way; the OAuth 2.0 default of HTTP Basic is
# rejected by the registration.
token_endpoint_auth_method = "client_secret_post"
end_session_endpoint = "http://localhost:8080/oauth2/sessions/logout"
EOF
}

write_config "$temporary/primary.toml" "$primary_port" "$primary_origin" e6irc_primary e6irc-primary "$primary_secret"
write_config "$temporary/secondary.toml" "$secondary_port" "$secondary_origin" e6irc_secondary e6irc-secondary "$secondary_secret"

# Cargo honours CARGO_TARGET_DIR, so the artifact is not always under ./target;
# run the binary the build actually produced.
e6ircd="${CARGO_TARGET_DIR:-$root/target}/debug/e6ircd"
if [[ ! -x "$e6ircd" ]]; then
  echo "e6ircd was not built at $e6ircd" >&2
  exit 2
fi

env -i HOME="$HOME" PATH="$PATH" RUST_BACKTRACE=1 \
  "$e6ircd" --config "$temporary/primary.toml" >"$temporary/primary.log" 2>&1 &
primary_pid=$!
env -i HOME="$HOME" PATH="$PATH" RUST_BACKTRACE=1 \
  "$e6ircd" --config "$temporary/secondary.toml" >"$temporary/secondary.log" 2>&1 &
secondary_pid=$!

for port in "$primary_port" "$secondary_port"; do
  for _ in $(seq 1 150); do
    if curl --fail --silent "http://localhost:$port/healthz" >/dev/null 2>&1; then
      break
    fi
    sleep 0.1
  done
  curl --fail --silent --show-error "http://localhost:$port/healthz" >/dev/null
done

SHAUTH_VALIDATOR_USERNAME=admin \
SHAUTH_BOOTSTRAP_ADMIN_PASSWORD="$SHAUTH_BOOTSTRAP_ADMIN_PASSWORD" \
E6IRC_NON_AUTHENTIC_CREDENTIAL_SENTINEL="$E6IRC_NON_AUTHENTIC_CREDENTIAL_SENTINEL" \
E6IRC_TEST_REVISION="$E6IRC_TEST_REVISION" \
  pnpm -C "$root/web" exec node "$root/tools/test-shauth-sso.mjs"
