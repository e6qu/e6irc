#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_PROBE_REPORT:?}"

if [[ $# -lt 2 ]]; then
  echo 'usage: scale-probe.sh LOAD_BIN RESULT_JSON [LOAD_ARGS...]' >&2
  exit 2
fi

load_bin="$1"
result="$2"
shift 2

set +e
"$load_bin" "$@"
set -e

if [[ -f "$result" ]] && jq -e '.status == "completed" and .report.outcome == "passed"' "$result" >/dev/null; then
  report='{"authentication":"passed","delivery":"passed","reconnect":"not_applicable","cleanup":"passed","persistence":"not_applicable"}'
elif [[ -f "$result" ]] && jq -e '.status == "completed" and .report.outcome == "rejected"' "$result" >/dev/null; then
  report='{"authentication":"rejected","delivery":"rejected","reconnect":"not_applicable","cleanup":"rejected","persistence":"not_applicable"}'
else
  report='{"authentication":"failed","delivery":"failed","reconnect":"not_applicable","cleanup":"failed","persistence":"not_applicable"}'
fi
printf '%s\n' "$report" >"$E6IRC_QUALIFICATION_PROBE_REPORT"
