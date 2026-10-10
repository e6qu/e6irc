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

# A refused first database connection exits in milliseconds; without this the
# default start limit (5 in 10 s) turns a PostgreSQL that comes up later than
# e6ircd into a unit that stays failed until a human resets it.
grep -qx 'StartLimitIntervalSec=0' "$unit" || {
  echo "$unit must set StartLimitIntervalSec=0 so a slow database cannot leave the unit permanently failed" >&2
  exit 1
}

# A core file is a copy of the process's memory, which holds the master key,
# opened upstream credentials, and session tokens. The daemon also marks itself
# non-dumpable at start (PR_SET_DUMPABLE); the unit refuses core files so the
# kernel writes none even before that call or if it fails.
grep -qx 'LimitCORE=0' "$unit" || {
  echo "$unit must set LimitCORE=0: a core file would carry the master key and opened credentials" >&2
  exit 1
}

# The daemon's clean shutdown is sequential: its listeners close for up to
# SHUTDOWN_LISTENER_CLOSE_TIMEOUT, THEN the bouncer drivers say goodbye
# for up to SHUTDOWN_DRIVER_STOP_TIMEOUT, THEN the core shards drain for up to
# SHUTDOWN_CORE_STOP_TIMEOUT, THEN the client connections deliver their closing
# ERROR for up to SHUTDOWN_CONNECTION_DRAIN_TIMEOUT, THEN the database flushes
# for up to SHUTDOWN_DB_FLUSH_TIMEOUT, THEN the serving lease is given back for
# up to SHUTDOWN_LEASE_RELEASE_TIMEOUT. The unit's stop budget must exceed the
# sum, or systemd can kill a shutdown that was still clean.
stop_seconds="$(sed -n 's/^TimeoutStopSec=\([0-9][0-9]*\)s$/\1/p' "$unit")"
flush_seconds="$(sed -n 's/.*const SHUTDOWN_DB_FLUSH_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
drain_seconds="$(sed -n 's/.*const SHUTDOWN_CORE_STOP_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
driver_seconds="$(sed -n 's/.*const SHUTDOWN_DRIVER_STOP_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
connection_seconds="$(sed -n 's/.*const SHUTDOWN_CONNECTION_DRAIN_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
release_seconds="$(sed -n 's/.*const SHUTDOWN_LEASE_RELEASE_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
listener_seconds="$(sed -n 's/.*const SHUTDOWN_LISTENER_CLOSE_TIMEOUT.*from_secs(\([0-9][0-9]*\)).*/\1/p' crates/e6ircd/src/net.rs | head -n1)"
if [ -z "$stop_seconds" ] || [ -z "$flush_seconds" ] || [ -z "$drain_seconds" ] || [ -z "$driver_seconds" ] || [ -z "$connection_seconds" ] || [ -z "$release_seconds" ] || [ -z "$listener_seconds" ]; then
  echo "could not resolve the systemd stop budget or the daemon's listener-close/driver-stop/drain/connection/flush/lease-release budgets" >&2
  exit 1
fi
budget=$((listener_seconds + driver_seconds + drain_seconds + connection_seconds + flush_seconds + release_seconds))
if [ "$stop_seconds" -le "$budget" ]; then
  echo "TimeoutStopSec=${stop_seconds}s must exceed the daemon's ${listener_seconds}s listener close plus ${driver_seconds}s driver stop plus ${drain_seconds}s core drain plus ${connection_seconds}s connection drain plus ${flush_seconds}s database flush plus ${release_seconds}s lease release (${budget}s)" >&2
  exit 1
fi

# The operator documentation and the production-container test state the same
# stop budget as the unit: deploy/README.md tells a host how long to wait, and
# tools/test-production-container.sh stops the image with it. A literal number
# in either drifts the moment the unit's budget changes.
readme="deploy/README.md"
for pattern in \
  '\([0-9][0-9]*\)-second stop budget' \
  'at least \([0-9][0-9]*\) seconds' \
  'stopTimeout: \([0-9][0-9]*\)' \
  'docker stop --time \([0-9][0-9]*\)' \
  'stop_grace_period: \([0-9][0-9]*\)s'; do
  values="$(sed -n "s/^\\(.*[^0-9]\\)\\{0,1\\}${pattern}.*/\\2/p" "$readme")"
  if [ -z "$values" ]; then
    echo "$readme no longer states the stop budget as '${pattern}'; update this check to match its wording" >&2
    exit 1
  fi
  for value in $values; do
    if [ "$value" != "$stop_seconds" ]; then
      echo "$readme states a ${value}-second stop budget ('${pattern}') but $unit has TimeoutStopSec=${stop_seconds}s" >&2
      exit 1
    fi
  done
done

container_test="tools/test-production-container.sh"
if grep -Eq 'docker stop .*--time[ =]*[0-9]' "$container_test"; then
  echo "$container_test stops the container with a literal budget; read it from $unit's TimeoutStopSec" >&2
  exit 1
fi
if ! grep -q 'TimeoutStopSec' "$container_test" || ! grep -q 'docker stop --time "\$stop_seconds"' "$container_test"; then
  echo "$container_test must stop the container with the budget it reads from $unit's TimeoutStopSec" >&2
  exit 1
fi
