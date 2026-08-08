#!/usr/bin/env bash
# Walk e6irc-load across increasing client counts against a running
# e6ircd and print one result line per count. The server must already be
# listening at $ADDR.
#
#   tools/load/sweep.sh [ADDR] [COUNTS] [BURST] [--report-dir DIR] [E6IRC-LOAD OPTIONS...]
#
# Defaults: ADDR=127.0.0.1:6667, COUNTS="100 500 1000 5000", BURST=20.
set -euo pipefail

ADDR="${1:-127.0.0.1:6667}"
COUNTS="${2:-100 500 1000 5000}"
BURST="${3:-20}"
EXTRA_ARGS=("${@:4}")
REPORT_DIR=""
FILTERED_ARGS=()
for ((index = 0; index < ${#EXTRA_ARGS[@]}; index++)); do
  arg="${EXTRA_ARGS[index]}"
  if [[ "$arg" == "--report-dir" ]]; then
    [[ -z "$REPORT_DIR" ]] || { echo "--report-dir may appear once" >&2; exit 2; }
    index=$((index + 1))
    REPORT_DIR="${EXTRA_ARGS[index]:-}"
    [[ -n "$REPORT_DIR" && "$REPORT_DIR" != -* ]] || {
      echo "--report-dir needs a directory" >&2
      exit 2
    }
  elif [[ "$arg" == "--report-json" ]]; then
    echo "use --report-dir for a sweep; each client count needs its own report" >&2
    exit 2
  else
    FILTERED_ARGS+=("$arg")
  fi
done
EXTRA_ARGS=("${FILTERED_ARGS[@]}")

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN="$ROOT/target/release/e6irc-load"
if [[ ! -x "$BIN" ]]; then
  echo "building e6irc-load (release)..." >&2
  (cd "$ROOT" && cargo build --release -p e6irc-load >&2)
fi
if [[ -n "$REPORT_DIR" ]]; then
  [[ ! -e "$REPORT_DIR" ]] || { echo "report directory already exists: $REPORT_DIR" >&2; exit 2; }
  mkdir -p "$REPORT_DIR"
fi

echo "sweep against $ADDR (burst=$BURST)"
for n in $COUNTS; do
  echo "--- clients=$n ---"
  run_args=(--addr "$ADDR" --clients "$n" --burst "$BURST" "${EXTRA_ARGS[@]}")
  if [[ -n "$REPORT_DIR" ]]; then
    run_args+=(--report-json "$REPORT_DIR/$n.json")
  fi
  "$BIN" "${run_args[@]}"
done
