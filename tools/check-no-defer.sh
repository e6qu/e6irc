#!/usr/bin/env bash
# Guard the No-Deferral Rule. Portable to bash 3.2.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# BUGS.md is a tripwire, not a backlog.
if grep -nE '^[[:space:]]*-[[:space:]]*\[[[:space:]]\]' BUGS.md >/dev/null 2>&1; then
  echo "no-defer guard: BUGS.md has open bug entries — fix them, or put the"
  echo "                decision to the human. BUGS.md is a tripwire, not a backlog:"
  grep -nE '^[[:space:]]*-[[:space:]]*\[[[:space:]]\]' BUGS.md
  fail=1
fi

# Check only newly added PLAN.md lines.
base="${1:-origin/main}"
if git rev-parse --verify -q "$base" >/dev/null 2>&1; then
  added="$(git diff "$base" -- PLAN.md | grep '^+' | grep -v '^+++' || true)"
  banned='surfaced, not (done|changed)|deferred to a (dedicated|future) (pass|sweep)|noted for a (dedicated|future) (pass|sweep)|left (for|to) a (later|future) (pass|sweep)|considered non-change|gold-plat'
  hits="$(printf '%s\n' "$added" | grep -niE "$banned" || true)"
  if [ -n "$hits" ]; then
    echo "no-defer guard: this change adds a deferral idiom to PLAN.md. Address the"
    echo "                item, or escalate it to the human as an explicit decision —"
    echo "                do not file it as done-later:"
    printf '%s\n' "$hits"
    fail=1
  fi
else
  echo "no-defer guard: base ref '$base' not found; skipping the PLAN.md diff check"
  echo "                (pass a base ref as \$1, e.g. tools/check-no-defer.sh main)."
fi

if [ "$fail" -eq 0 ]; then
  echo "no-defer guard: clean (no deferral vehicle in use)"
fi
exit "$fail"
