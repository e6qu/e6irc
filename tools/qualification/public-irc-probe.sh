#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_TARGET:?}"
source "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/report.sh"

case "$E6IRC_QUALIFICATION_TARGET" in
  libera) test=live_driver_connects_to_libera ;;
  oftc) test=live_driver_connects_to_oftc ;;
  ergo) test=live_driver_connects_to_ergo ;;
  *)
    write_probe_report not_run not_applicable not_run not_run not_applicable
    exit 0
    ;;
esac

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
if (cd "$root" && cargo test -p e6ircd --lib "$test" -- --ignored --nocapture); then
  write_probe_report passed not_applicable passed passed not_applicable
else
  exit 1
fi
