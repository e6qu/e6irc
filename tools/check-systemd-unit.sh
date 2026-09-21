#!/usr/bin/env bash
set -euo pipefail

unit="deploy/e6ircd.service"
if ! command -v systemd-analyze >/dev/null 2>&1; then
  echo "systemd-analyze is required to validate ${unit}" >&2
  exit 1
fi

# `verify` otherwise treats the deliberately external installed binary as a
# missing ExecStart. A private root supplies only that executable and the unit;
# none of the host's service definitions can affect this check.
check_root="$(mktemp -d)"
trap 'rm -rf "$check_root"' EXIT
mkdir -p "$check_root/etc/systemd/system" "$check_root/usr/local/bin"
cp "$unit" "$check_root/etc/systemd/system/e6ircd.service"
touch "$check_root/usr/local/bin/e6ircd"
chmod 0755 "$check_root/usr/local/bin/e6ircd"
systemd-analyze \
  --root="$check_root" \
  --recursive-errors=no \
  --man=no \
  verify e6ircd.service

# The daemon's clean shutdown is sequential: the core shards drain for up to
# SHUTDOWN_CORE_STOP_TIMEOUT, THEN the database flushes for up to
# SHUTDOWN_DB_FLUSH_TIMEOUT. The unit's stop budget must exceed the sum, or
# systemd can kill a shutdown that was still clean.
stop_seconds="$(sed -n 's/^TimeoutStopSec=\([0-9][0-9]*\)s$/\1/p' "$unit")"
flush_seconds="$(sed -n 's/.*const SHUTDOWN_DB_FLUSH_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
drain_seconds="$(sed -n 's/.*const SHUTDOWN_CORE_STOP_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
if [ -z "$stop_seconds" ] || [ -z "$flush_seconds" ] || [ -z "$drain_seconds" ]; then
  echo "could not resolve the systemd stop budget or the daemon's drain/flush budgets" >&2
  exit 1
fi
budget=$((drain_seconds + flush_seconds))
if [ "$stop_seconds" -le "$budget" ]; then
  echo "TimeoutStopSec=${stop_seconds}s must exceed the daemon's ${drain_seconds}s core drain plus ${flush_seconds}s database flush (${budget}s)" >&2
  exit 1
fi
