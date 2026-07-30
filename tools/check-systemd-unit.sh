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
