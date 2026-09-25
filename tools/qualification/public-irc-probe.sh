#!/usr/bin/env bash
set -euo pipefail

: "${E6IRC_QUALIFICATION_TARGET:?}"
source "$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)/report.sh"

# Two ignored suites per target: the BNC driver's (registration, reconnect,
# channel traffic) and the client library's (the greeting and the ISUPPORT
# tokens every consumer reads).
case "$E6IRC_QUALIFICATION_TARGET" in
  libera) test=live_driver_connects_to_libera compat=interoperates_with_libera ;;
  oftc) test=live_driver_connects_to_oftc compat=interoperates_with_oftc ;;
  ergo) test=live_driver_connects_to_ergo compat=interoperates_with_ergo ;;
  *)
    write_probe_report not_run not_applicable not_run not_run not_applicable
    exit 0
    ;;
esac

root="$(CDPATH='' cd -- "$(dirname -- "$0")/../.." && pwd)"
log="$(mktemp)"
trap 'rm -f "$log"' EXIT

# A filter that matches nothing passes with zero tests run, so a renamed test
# would turn the probe into a silent pass: require exactly one to have passed.
run_one() { # CARGO_TEST_ARGS...
  (cd "$root" && cargo test --locked -p e6ircd "$@" -- --ignored --nocapture) 2>&1 | tee "$log"
  [[ ${PIPESTATUS[0]} -eq 0 ]] || return 1
  grep -q '^test result: ok\. 1 passed;' "$log" || {
    echo "public-irc probe: '$*' did not run exactly one test" >&2
    return 1
  }
}

if run_one --lib "$test" && run_one --test live_compat "$compat"; then
  write_probe_report passed not_applicable passed passed not_applicable
else
  exit 1
fi
