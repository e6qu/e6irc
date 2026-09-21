#!/usr/bin/env bash
# Guard the No-Deferral Rule. Portable to bash 3.2.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# BUGS.md is a tripwire, not a backlog. A tripwire that is gone or unreadable
# has not been checked, so that is a failure too, not a clean result.
open_entry='^[[:space:]]*-[[:space:]]*\[[[:space:]]\]'
if [ ! -f BUGS.md ] || [ ! -r BUGS.md ]; then
  echo "no-defer guard: BUGS.md is missing or unreadable — the tripwire must exist"
  echo "                (and stay empty) for this guard to mean anything."
  fail=1
elif grep -nE "$open_entry" BUGS.md; then
  echo "no-defer guard: BUGS.md has the open bug entries above — fix them, or put"
  echo "                the decision to the human. BUGS.md is a tripwire, not a backlog."
  fail=1
fi

# Check only newly added PLAN.md lines.
base="${1:-origin/main}"
if ! git rev-parse --verify -q "$base^{commit}" >/dev/null; then
  echo "no-defer guard: base ref '$base' does not resolve, so the PLAN.md additions"
  echo "                cannot be examined. Fetch it, or pass one that exists"
  echo "                (e.g. tools/check-no-defer.sh main)."
  exit 1
fi
plan_diff="$(git diff "$base" -- PLAN.md)"
added="$(printf '%s\n' "$plan_diff" | grep '^+' | grep -v '^+++' || true)"
banned='surfaced, not (done|changed)|deferred to a (dedicated|future) (pass|sweep)|noted for a (dedicated|future) (pass|sweep)|left (for|to) a (later|future) (pass|sweep)|considered non-change|gold-plat'
hits="$(printf '%s\n' "$added" | grep -niE "$banned" || true)"
if [ -n "$hits" ]; then
  echo "no-defer guard: this change adds a deferral idiom to PLAN.md. Address the"
  echo "                item, or escalate it to the human as an explicit decision —"
  echo "                do not file it as done-later:"
  printf '%s\n' "$hits"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "no-defer guard: clean (no deferral vehicle in use)"
fi
exit "$fail"
