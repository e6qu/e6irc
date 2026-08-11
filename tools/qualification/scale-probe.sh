#!/usr/bin/env bash
set -euo pipefail

source "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/report.sh"

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
  report='passed passed not_applicable passed not_applicable'
elif [[ -f "$result" ]] && jq -e '.status == "completed" and .report.outcome == "rejected"' "$result" >/dev/null; then
  report='rejected rejected not_applicable rejected not_applicable'
else
  exit 1
fi
read -r -a phases <<<"$report"
write_probe_report "${phases[@]}"
