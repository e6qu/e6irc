#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
bin="$root/target/debug/e6irc-qualification"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

cargo build --quiet -p e6irc-qualification

probe() {
  local name="$1" report="$2"
  shift 2
  local path="$temporary/$name"
  printf '#!/usr/bin/env bash\nset -euo pipefail\nprintf %%s %q > "$E6IRC_QUALIFICATION_PROBE_REPORT"\n' "$report" >"$path"
  chmod +x "$path"
  printf '%s\n' "$path"
}

run() {
  local kind="$1"
  shift
  "$bin" "$kind" \
    --target example.test \
    --source aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
    --host qualification-host \
    --executable "$bin" \
    --workload sessions=1 \
    --budget timeout_seconds=1 \
    "$@"
}

passed='{"authentication":"passed","delivery":"passed","reconnect":"passed","cleanup":"passed","persistence":"passed"}'
rejected='{"authentication":"passed","delivery":"rejected","reconnect":"passed","cleanup":"passed","persistence":"passed"}'

pass_probe="$(probe pass "$passed")"
run public-irc --output "$temporary/passed.json" --probe "$pass_probe"
jq -e '
  .kind == "public_irc" and .outcome == "passed" and
  (.probe | .authentication == "passed" and .delivery == "passed" and .reconnect == "passed" and .cleanup == "passed" and .persistence == "passed") and
  (.executable.sha256 | test("^[0-9a-f]{64}$"))
' "$temporary/passed.json" >/dev/null
! find "$temporary" -name '*.probe.json' -print -quit | grep -q .

if run public-irc --output "$temporary/public-rejected.json" --probe "$root/tools/qualification/public-irc-probe.sh"; then
  echo 'unknown public IRC target unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "public_irc" and .outcome == "rejected" and .probe.delivery == "not_applicable"' "$temporary/public-rejected.json" >/dev/null

reject_probe="$(probe reject "$passed")"
if E6IRC_DISCORD_BOT_TOKEN='' run discord --output "$temporary/rejected.json" --probe "$reject_probe"; then
  echo 'missing credential unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "discord" and .outcome == "rejected" and ([.probe[]] | all(. == "rejected"))' "$temporary/rejected.json" >/dev/null

failure_probe="$(probe failure '{not-json')"
if E6IRC_DISCORD_BOT_TOKEN='literal-secret-token' run discord --output "$temporary/failed.json" --probe "$failure_probe"; then
  echo 'malformed probe report unexpectedly passed' >&2
  exit 1
fi
jq -e '.kind == "discord" and .outcome == "failed" and ([.probe[]] | all(. == "failed"))' "$temporary/failed.json" >/dev/null
! rg -F 'literal-secret-token' "$temporary/failed.json"

slack_probe="$(probe slack "$passed")"
E6IRC_SLACK_BOT_TOKEN='literal-slack-bot' E6IRC_SLACK_APP_TOKEN='literal-slack-app' E6IRC_SLACK_PROBE="$slack_probe" \
  run slack --output "$temporary/slack-passed.json" --probe "$root/tools/qualification/external-probe.sh"
jq -e '.kind == "slack" and .outcome == "passed"' "$temporary/slack-passed.json" >/dev/null
! rg -F 'literal-slack-' "$temporary/slack-passed.json"

partial_probe="$(probe partial "$rejected")"
if run scale --output "$temporary/partial.json" --probe "$partial_probe"; then
  echo 'partial qualification unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "scale" and .outcome == "rejected" and .probe.delivery == "rejected"' "$temporary/partial.json" >/dev/null

load="$temporary/load"
printf '#!/usr/bin/env bash\nprintf %%s %q > %q\n' \
  '{"status":"completed","report":{"outcome":"rejected"}}' "$temporary/load.json" >"$load"
chmod +x "$load"
if run scale --output "$temporary/scale.json" --probe "$root/tools/qualification/scale-probe.sh" -- "$load" "$temporary/load.json"; then
  echo 'rejected scale probe unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "scale" and .outcome == "rejected" and .probe.persistence == "not_applicable"' "$temporary/scale.json" >/dev/null

load_pass="$temporary/load-pass"
printf '#!/usr/bin/env bash\nprintf %%s %q > %q\n' \
  '{"status":"completed","report":{"outcome":"passed"}}' "$temporary/load-pass.json" >"$load_pass"
chmod +x "$load_pass"
run scale --output "$temporary/scale-passed.json" --probe "$root/tools/qualification/scale-probe.sh" -- "$load_pass" "$temporary/load-pass.json"
jq -e '.kind == "scale" and .outcome == "passed" and .probe.persistence == "not_applicable"' "$temporary/scale-passed.json" >/dev/null

if run oidc --output "$temporary/oidc-rejected.json" --probe "$root/tools/qualification/external-probe.sh"; then
  echo 'missing OIDC credential unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "oidc" and .outcome == "rejected"' "$temporary/oidc-rejected.json" >/dev/null

oidc_probe="$(probe oidc '{"authentication":"passed","delivery":"not_applicable","reconnect":"passed","cleanup":"passed","persistence":"passed"}')"
E6IRC_OIDC_CLIENT_SECRET='literal-oidc-secret' E6IRC_OIDC_PROBE="$oidc_probe" \
  run oidc --output "$temporary/oidc-passed.json" --probe "$root/tools/qualification/external-probe.sh"
jq -e '.kind == "oidc" and .outcome == "passed" and .probe.delivery == "not_applicable"' "$temporary/oidc-passed.json" >/dev/null
! rg -F 'literal-oidc-secret' "$temporary/oidc-passed.json"
