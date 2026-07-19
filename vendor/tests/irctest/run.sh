#!/usr/bin/env bash
# Run irctest against a locally built e6ircd. Subshell-safe: never
# changes the caller's working directory.
#   vendor/tests/irctest/run.sh <irctest-checkout> <python-with-deps> [pytest args...]
set -euo pipefail
IRCTEST_DIR=$1
PYTHON=$2
shift 2
REPO_ROOT=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
MARKERS='not implementation-specific and not deprecated and not strict and not services'
(
    cd -- "$IRCTEST_DIR"
    PATH="$REPO_ROOT/target/debug:$PATH" \
    PYTHONPATH="$REPO_ROOT/vendor/tests/irctest" \
    "$PYTHON" -m pytest --controller=e6ircd_controller --timeout=8 \
        -m "$MARKERS" "$@"
)
