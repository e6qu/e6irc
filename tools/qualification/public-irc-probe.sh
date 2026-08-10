#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_PROBE_REPORT:?}"
: "${E6IRC_QUALIFICATION_TARGET:?}"

case "$E6IRC_QUALIFICATION_TARGET" in
  libera) test=interoperates_with_libera ;;
  oftc) test=interoperates_with_oftc ;;
  ergo) test=interoperates_with_ergo ;;
  *)
    printf '%s\n' '{"authentication":"rejected","delivery":"not_applicable","reconnect":"rejected","cleanup":"rejected","persistence":"not_applicable"}' >"$E6IRC_QUALIFICATION_PROBE_REPORT"
    exit 0
    ;;
esac

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
if (cd "$root" && cargo test -p e6ircd --test live_compat "$test" -- --ignored --nocapture); then
  printf '%s\n' '{"authentication":"passed","delivery":"not_applicable","reconnect":"passed","cleanup":"passed","persistence":"not_applicable"}' >"$E6IRC_QUALIFICATION_PROBE_REPORT"
else
  printf '%s\n' '{"authentication":"failed","delivery":"not_applicable","reconnect":"failed","cleanup":"failed","persistence":"not_applicable"}' >"$E6IRC_QUALIFICATION_PROBE_REPORT"
fi
