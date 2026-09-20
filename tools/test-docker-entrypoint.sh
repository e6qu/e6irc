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

base_environment=(
  TMPDIR="$scratch"
  E6IRC_BINARY="$probe"
  E6IRC_TEST_RESULT="$result"
  E6IRC_SERVER_NAME="irc.example.test"
  E6IRC_PUBLIC_URL="https://irc.example.test"
  E6IRC_DATABASE_URL="postgres://example.invalid/e6irc"
  APPLICATION_RELEASE_REVISION="0123456789ab"
)

# Empty fields in the administrator list name no account. A trailing comma used
# to end the render loop on a failed test, which `set -e` turned into an exit
# with nothing in the container log.
for accounts in 'alice,' 'alice,,bob' ',alice'; do
  env "${base_environment[@]}" E6IRC_ADMIN_ACCOUNTS="$accounts" \
    sh "$workspace/deploy/docker-entrypoint.sh"
  case "$accounts" in
    *bob*) expected='admin_accounts = ["alice", "bob", ]' ;;
    *) expected='admin_accounts = ["alice", ]' ;;
  esac
  grep -Fx "$expected" "$result" >/dev/null || {
    echo "E6IRC_ADMIN_ACCOUNTS='$accounts' did not render $expected" >&2
    exit 1
  }
  "$workspace/target/debug/e6ircd" check-config --config "$(sed -n '1p' "$result")"
done

# A value carrying a control character is refused by variable name. Rendered, it
# would be a TOML parse error on the line holding the secret, and the refusal
# must not be the thing that prints it.
refusal="$scratch/refusal"
carriage_return=$'\r'
newline=$'\n'
delete=$'\x7f'
refused() { # VARIABLE VALUE [further VARIABLE=VALUE ...]
  local variable="$1" value="$2"
  shift 2
  : > "$scratch/commands"
  if env "${base_environment[@]}" E6IRC_TEST_COMMANDS="$scratch/commands" "$@" \
    "$variable=$value" sh "$workspace/deploy/docker-entrypoint.sh" > "$refusal" 2>&1; then
    echo "entrypoint accepted an unrenderable $variable" >&2
    exit 1
  fi
  grep -F "$variable" "$refusal" >/dev/null || {
    echo "the refusal of $variable does not name it:" >&2
    cat "$refusal" >&2
    exit 1
  }
  if grep -F 'hunter2' "$refusal" >&2; then
    echo "the refusal of $variable printed its value" >&2
    exit 1
  fi
  [ ! -s "$scratch/commands" ] || {
    echo "e6ircd was started despite an unrenderable $variable" >&2
    exit 1
  }
}
oidc=(
  E6IRC_OIDC_ISSUER="https://auth.example.test"
  E6IRC_OIDC_CLIENT_ID="e6irc-dev"
  E6IRC_OIDC_CLIENT_SECRET="hunter2"
  E6IRC_OIDC_END_SESSION="https://auth.example.test/oauth2/sessions/logout"
)
refused E6IRC_DATABASE_URL "postgres://user:hunter2@example.invalid/e6irc$carriage_return"
refused E6IRC_DATABASE_URL "postgres://user:hunter2@example.invalid/e6irc$newline"
refused E6IRC_BOOTSTRAP_TOKEN "hunter2-0123456789abcdef0123456789abcdef$delete"
refused E6IRC_OIDC_CLIENT_SECRET "hunter2${newline}injected = true" "${oidc[@]}"
refused E6IRC_ADMIN_ACCOUNTS "alice,hunter2$carriage_return"
for cookies in 'yes' 'true # hunter2' "true${newline}admin_accounts = [\"hunter2\"]"; do
  refused E6IRC_SECURE_COOKIES "$cookies"
done
env "${base_environment[@]}" E6IRC_SECURE_COOKIES=false sh "$workspace/deploy/docker-entrypoint.sh"
grep -Fx 'secure_cookies = false' "$result" >/dev/null

# The daemon's own report of an unparsable file gives the position and the
# reason, never the source line: that line is as likely a secret as not.
unparsable="$scratch/unparsable.toml"
printf 'server_name = "irc.example.test"\n[database]\nurl = "postgres://user:hunter2@example.invalid/e6irc\r"\n' > "$unparsable"
if "$workspace/target/debug/e6ircd" check-config --config "$unparsable" > "$refusal" 2>&1; then
  echo 'check-config accepted a control character inside a string' >&2
  exit 1
fi
grep -F 'line 3, column' "$refusal" >/dev/null || {
  echo 'check-config did not say where the configuration is unparsable:' >&2
  cat "$refusal" >&2
  exit 1
}
if grep -F 'hunter2' "$refusal" >&2; then
  echo 'check-config printed the unparsable source line' >&2
  exit 1
fi

echo "docker entrypoint contract ok"
