#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

cargo build -p e6ircd

incomplete="$scratch/incomplete.toml"
printf '%s\n' 'server_name = "irc.example.test"' > "$incomplete"
if "$workspace/target/debug/e6ircd" check-config --config "$incomplete" 2>/dev/null; then
  echo 'check-config accepted incomplete configuration' >&2
  exit 1
fi

probe="$scratch/e6ircd-probe"
result="$scratch/result"
cat > "$probe" <<'PROBE'
#!/bin/sh
set -eu
if [ -n "${E6IRC_TEST_COMMANDS:-}" ]; then
  printf '%s\n' "$1" >> "$E6IRC_TEST_COMMANDS"
fi
case "$1" in
  check-config)
    [ "$2" = "--config" ]
    config="$3"
    ;;
  --config) config="$2" ;;
  *) exit 1 ;;
esac
mode="$(stat -c '%a' "$config" 2>/dev/null || stat -f '%Lp' "$config")"
printf '%s\n' "$config" "$mode" > "$E6IRC_TEST_RESULT"
cat "$config" >> "$E6IRC_TEST_RESULT"
PROBE
chmod 0700 "$probe"

env \
  TMPDIR="$scratch" \
  E6IRC_BINARY="$probe" \
  E6IRC_TEST_COMMANDS="$scratch/commands" \
  E6IRC_TEST_RESULT="$result" \
  E6IRC_SERVER_NAME="irc.example.test" \
  E6IRC_PUBLIC_URL="https://irc.example.test" \
  E6IRC_DATABASE_URL="postgres://example.invalid/e6irc" \
  E6IRC_BOOTSTRAP_TOKEN="0123456789abcdef0123456789abcdef" \
  APPLICATION_RELEASE_REVISION="0123456789ab" \
  sh "$workspace/deploy/docker-entrypoint.sh"

config_path="$(sed -n '1p' "$result")"
mode="$(sed -n '2p' "$result")"
case "$config_path" in
  "$scratch"/e6irc.*) ;;
  *)
    echo "entrypoint used a predictable default config path: $config_path" >&2
    exit 1
    ;;
esac
[ "$mode" = "600" ] || {
  echo "entrypoint config mode is $mode, expected 600" >&2
  exit 1
}
grep -F 'server_name = "irc.example.test"' "$result" >/dev/null
grep -F 'public_url = "https://irc.example.test"' "$result" >/dev/null
grep -F 'token = "0123456789abcdef0123456789abcdef"' "$result" >/dev/null
diff -u <(printf '%s\n' check-config --config) "$scratch/commands"
"$workspace/target/debug/e6ircd" check-config --config "$config_path"

explicit="$scratch/operator.toml"
env \
  E6IRC_BINARY="$probe" \
  E6IRC_TEST_RESULT="$result" \
  E6IRC_CONFIG_PATH="$explicit" \
  E6IRC_SERVER_NAME="irc.example.test" \
  E6IRC_PUBLIC_URL="https://irc.example.test" \
  E6IRC_DATABASE_URL="postgres://example.invalid/e6irc" \
  APPLICATION_RELEASE_REVISION="0123456789ab" \
  sh "$workspace/deploy/docker-entrypoint.sh"
[ "$(sed -n '1p' "$result")" = "$explicit" ]
[ "$(sed -n '2p' "$result")" = "600" ]
"$workspace/target/debug/e6ircd" check-config --config "$explicit"

# The OIDC branch was never exercised here, and it shipped a config e6ircd's own
# parser rejects: OidcProviderConfig::account_claim carries no serde default, so
# the omission failed the whole parse and the container crash-looped with
# "invalid config: missing field `account_claim`" before it ever listened. Every
# field the provider struct requires must therefore appear in the rendered block.
env \
  TMPDIR="$scratch" \
  E6IRC_BINARY="$probe" \
  E6IRC_TEST_RESULT="$result" \
  E6IRC_SERVER_NAME="irc.example.test" \
  E6IRC_PUBLIC_URL="https://irc.example.test" \
  E6IRC_DATABASE_URL="postgres://example.invalid/e6irc" \
  APPLICATION_RELEASE_REVISION="0123456789ab" \
  E6IRC_OIDC_ISSUER="https://auth.example.test" \
  E6IRC_OIDC_CLIENT_ID="e6irc-dev" \
  E6IRC_OIDC_CLIENT_SECRET="s3cr3t" \
  E6IRC_OIDC_END_SESSION="https://auth.example.test/oauth2/sessions/logout" \
  sh "$workspace/deploy/docker-entrypoint.sh"

for field in name issuer_url client_id client_secret account_claim \
  token_endpoint_auth_method end_session_endpoint; do
  grep -E "^$field = " "$result" >/dev/null || {
    echo "entrypoint rendered an [[oidc]] block without a $field; e6ircd requires it" >&2
    exit 1
  }
done
grep -F 'account_claim = "preferred_username"' "$result" >/dev/null
"$workspace/target/debug/e6ircd" check-config --config "$(sed -n '1p' "$result")"

# ...and the claim stays operator-selectable.
env \
  TMPDIR="$scratch" \
  E6IRC_BINARY="$probe" \
  E6IRC_TEST_RESULT="$result" \
  E6IRC_SERVER_NAME="irc.example.test" \
  E6IRC_PUBLIC_URL="https://irc.example.test" \
  E6IRC_DATABASE_URL="postgres://example.invalid/e6irc" \
  APPLICATION_RELEASE_REVISION="0123456789ab" \
  E6IRC_OIDC_ISSUER="https://auth.example.test" \
  E6IRC_OIDC_CLIENT_ID="e6irc-dev" \
  E6IRC_OIDC_CLIENT_SECRET="s3cr3t" \
  E6IRC_OIDC_END_SESSION="https://auth.example.test/oauth2/sessions/logout" \
  E6IRC_OIDC_ACCOUNT_CLAIM="email" \
  sh "$workspace/deploy/docker-entrypoint.sh"
grep -F 'account_claim = "email"' "$result" >/dev/null
"$workspace/target/debug/e6ircd" check-config --config "$(sed -n '1p' "$result")"
