#!/usr/bin/env bash
# Walk e6irc-load across increasing client counts against a running
# e6ircd and print one result line per count. The server must already be
# listening at $ADDR.
#
#   tools/load/sweep.sh [ADDR] [COUNTS] [BURST]
#
# Defaults: ADDR=127.0.0.1:6667, COUNTS="100 500 1000 5000", BURST=20.
set -euo pipefail

ADDR="${1:-127.0.0.1:6667}"
COUNTS="${2:-100 500 1000 5000}"
BURST="${3:-20}"

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/release/e6irc-load"
if [[ ! -x "$BIN" ]]; then
  echo "building e6irc-load (release)..." >&2
  (cd "$ROOT" && cargo build --release -p e6irc-load >&2)
fi

echo "sweep against $ADDR (burst=$BURST)"
for n in $COUNTS; do
  echo "--- clients=$n ---"
  "$BIN" --addr "$ADDR" --clients "$n" --burst "$BURST"
done
