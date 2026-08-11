#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_PROBE_REPORT:?}"
: "${E6IRC_QUALIFICATION_CHALLENGE:?}"

write_probe_report() {
  [[ $# -eq 5 ]] || exit 2
  local phase
  for phase in "$@"; do
    case "$phase" in passed|rejected|failed|not_applicable|not_run) ;; *) exit 2 ;; esac
  done
  printf '{"challenge":"%s","authentication":"%s","delivery":"%s","reconnect":"%s","cleanup":"%s","persistence":"%s"}\n' \
    "$E6IRC_QUALIFICATION_CHALLENGE" "$1" "$2" "$3" "$4" "$5" >"$E6IRC_QUALIFICATION_PROBE_REPORT"
}
