#!/usr/bin/env bash
# Guard the No-Deferral Rule. Portable to bash 3.2.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# BUGS.md is a tripwire, not a backlog: it holds exactly this header and
# nothing else. Any addition fails — an open checkbox, a ticked one kept "for
# the record", a bare bullet or a paragraph are all the same backlog. A
# tripwire that is gone or unreadable has not been checked, so that is a
# failure too, not a clean result.
bugs_header='# e6irc — Known bugs

This file is a tripwire, not a backlog. It must stay empty.

Fix a defect in the current change or ask the human to decide. The no-defer
gate fails if this file gains anything beyond this header.'
if [ ! -f BUGS.md ] || [ ! -r BUGS.md ]; then
  echo "no-defer guard: BUGS.md is missing or unreadable — the tripwire must exist"
  echo "                (and stay empty) for this guard to mean anything."
  fail=1
elif ! printf '%s\n' "$bugs_header" | diff -u - BUGS.md; then
  echo "no-defer guard: BUGS.md differs from its fixed header (diff above) — fix"
  echo "                the defect, or put the decision to the human. BUGS.md is"
  echo "                a tripwire, not a backlog."
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
banned='surfaced, not (done|changed)|deferred to a (dedicated|future|later) (pass|sweep)|noted for a (dedicated|future|later) (pass|sweep)|left (for|to) a (later|future) (pass|sweep)|considered non-change|gold-plat'
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
