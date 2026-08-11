#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_TARGET:?}"
source "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/report.sh"

case "$E6IRC_QUALIFICATION_TARGET" in
  libera) test=interoperates_with_libera ;;
  oftc) test=interoperates_with_oftc ;;
  ergo) test=interoperates_with_ergo ;;
  *)
    write_probe_report not_run not_applicable not_run not_run not_applicable
    exit 0
    ;;
esac

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
if (cd "$root" && cargo test -p e6ircd --test live_compat "$test" -- --ignored --nocapture); then
  write_probe_report passed not_applicable passed passed not_applicable
else
  exit 1
fi
