#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_PROBE_REPORT:?}"

case "${E6IRC_QUALIFICATION_KIND:?}" in
  discord) command_name=E6IRC_DISCORD_PROBE ;;
  slack) command_name=E6IRC_SLACK_PROBE ;;
  oidc) command_name=E6IRC_OIDC_PROBE ;;
  *)
    echo 'external-probe.sh supports discord, slack, and oidc only' >&2
    exit 2
    ;;
esac

probe="${!command_name:-}"
if [[ ! -x "$probe" ]]; then
  printf '%s\n' '{"authentication":"rejected","delivery":"rejected","reconnect":"rejected","cleanup":"rejected","persistence":"rejected"}' >"$E6IRC_QUALIFICATION_PROBE_REPORT"
  exit 0
fi
"$probe"
