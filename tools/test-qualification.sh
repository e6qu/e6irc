#!/usr/bin/env bash
set -euo pipefail

root="$(CDPATH='' cd -- "$(dirname -- "$0")/.." && pwd)"
bin="$root/target/debug/e6irc-qualification"
temporary="$(mktemp -d)"
trap 'rm -rf "$temporary"' EXIT

cargo build -p e6irc-qualification

probe() {
  local name="$1" report="$2"
  shift 2
  local path="$temporary/$name"
  local report_tail="${report#\{}"
  {
    printf '%s\n' '#!/usr/bin/env bash' 'set -euo pipefail'
    printf '%s\n' 'printf %s '\''{"challenge":"'\'' > "$E6IRC_QUALIFICATION_PROBE_REPORT"'
    printf '%s\n' 'printf %s "$E6IRC_QUALIFICATION_CHALLENGE" >> "$E6IRC_QUALIFICATION_PROBE_REPORT"'
    printf '%s\n' 'printf %s '\''",'\'' >> "$E6IRC_QUALIFICATION_PROBE_REPORT"'
    printf 'printf %%s %q >> "$E6IRC_QUALIFICATION_PROBE_REPORT"\n' "$report_tail"
  } >"$path"
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

public_passed='{"authentication":"passed","delivery":"not_applicable","reconnect":"passed","cleanup":"passed","persistence":"not_applicable"}'
scale_rejected='{"authentication":"passed","delivery":"rejected","reconnect":"not_applicable","cleanup":"passed","persistence":"not_applicable"}'

pass_probe="$(probe pass "$public_passed")"
run public-irc --output "$temporary/passed.json" --probe "$pass_probe"
jq -e '
  .kind == "public_irc" and .outcome == "passed" and
  (.probe | .authentication == "passed" and .delivery == "not_applicable" and .reconnect == "passed" and .cleanup == "passed" and .persistence == "not_applicable") and
  (.executable.sha256 | test("^[0-9a-f]{64}$")) and
  (.executable | has("path") | not)
' "$temporary/passed.json" >/dev/null
! find "$temporary" -name '*.probe.json' -print -quit | grep -q .

occupied="$temporary/occupied.json"
printf '%s' retained >"$occupied"
if run public-irc --output "$occupied" --probe "$pass_probe"; then
  echo 'existing evidence was overwritten' >&2
  exit 1
else
  [[ $? -eq 2 ]]
fi
[[ "$(<"$occupied")" == retained ]]

stale_probe="$temporary/stale"
printf '%s\n' '#!/usr/bin/env bash' 'printf %s '\''{"challenge":"stale","authentication":"passed","delivery":"passed","reconnect":"passed","cleanup":"passed","persistence":"passed"}'\'' > "$E6IRC_QUALIFICATION_PROBE_REPORT"' >"$stale_probe"
chmod +x "$stale_probe"
if run public-irc --output "$temporary/stale.json" --probe "$stale_probe"; then
  echo 'stale report unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 1 ]]
fi
jq -e '.outcome == "failed" and .probe.authentication == "not_run" and .probe.delivery == "not_applicable" and .probe.reconnect == "not_run" and .probe.cleanup == "not_run" and .probe.persistence == "not_applicable"' "$temporary/stale.json" >/dev/null

invalid_applicability='{"authentication":"not_applicable","delivery":"not_applicable","reconnect":"passed","cleanup":"passed","persistence":"not_applicable"}'
invalid_applicability_probe="$(probe invalid-applicability "$invalid_applicability")"
if run public-irc --output "$temporary/invalid-applicability.json" --probe "$invalid_applicability_probe"; then
  echo 'invalid phase applicability unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 1 ]]
fi
jq -e '.outcome == "failed" and .probe.authentication == "not_run"' "$temporary/invalid-applicability.json" >/dev/null

if run public-irc --output "$temporary/public-rejected.json" --probe "$root/tools/qualification/public-irc-probe.sh"; then
  echo 'unknown public IRC target unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "public_irc" and .outcome == "rejected" and .probe.delivery == "not_applicable"' "$temporary/public-rejected.json" >/dev/null

if E6IRC_DISCORD_BOT_TOKEN='' run discord --output "$temporary/rejected.json"; then
  echo 'missing credential unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "discord" and .outcome == "rejected" and ([.probe[]] | all(. == "not_run"))' "$temporary/rejected.json" >/dev/null

if E6IRC_DISCORD_BOT_TOKEN='literal-secret-token' E6IRC_DISCORD_CHANNEL_ID='' \
  run discord --output "$temporary/missing-channel.json"; then
  echo 'missing Discord channel unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '
  .kind == "discord" and .outcome == "rejected" and
  (.credential_environment | sort == ["E6IRC_DISCORD_BOT_TOKEN", "E6IRC_DISCORD_CHANNEL_ID"]) and
  ([.probe[]] | all(. == "not_run"))
' "$temporary/missing-channel.json" >/dev/null

if E6IRC_DISCORD_BOT_TOKEN='literal-secret-token' E6IRC_DISCORD_CHANNEL_ID='42' \
  run discord --output "$temporary/invalid-probe.json" --probe "$pass_probe"; then
  echo 'native Discord campaign accepted an external probe' >&2
  exit 1
else
  [[ $? -eq 2 ]]
fi
[[ ! -e "$temporary/invalid-probe.json" ]]

partial_probe="$(probe partial "$scale_rejected")"
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

if run oidc --output "$temporary/oidc-rejected.json"; then
  echo 'missing OIDC credential unexpectedly passed' >&2
  exit 1
else
  [[ $? -eq 3 ]]
fi
jq -e '.kind == "oidc" and .outcome == "rejected"' "$temporary/oidc-rejected.json" >/dev/null
