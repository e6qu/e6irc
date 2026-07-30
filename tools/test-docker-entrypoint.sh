#!/usr/bin/env bash
set -euo pipefail

workspace="$(cd "$(dirname "$0")/.." && pwd)"
scratch="$(mktemp -d)"
trap 'rm -rf "$scratch"' EXIT

probe="$scratch/e6ircd-probe"
result="$scratch/result"
cat > "$probe" <<'PROBE'
#!/bin/sh
set -eu
[ "$1" = "--config" ]
mode="$(stat -c '%a' "$2" 2>/dev/null || stat -f '%Lp' "$2")"
printf '%s\n' "$2" "$mode" > "$E6IRC_TEST_RESULT"
cat "$2" >> "$E6IRC_TEST_RESULT"
PROBE
chmod 0700 "$probe"

env \
  TMPDIR="$scratch" \
  E6IRC_BINARY="$probe" \
  E6IRC_TEST_RESULT="$result" \
  E6IRC_SERVER_NAME="irc.example.test" \
  E6IRC_PUBLIC_URL="https://irc.example.test" \
  E6IRC_DATABASE_URL="postgres://example.invalid/e6irc" \
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
