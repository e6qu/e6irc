#!/usr/bin/env bash
# check-no-defer.sh — guard the No-Deferral Rule (AGENTS.md). A defect or
# worthwhile fix is addressed in the same change, or escalated to the human as
# an explicit decision — never filed away to be done "later". This guard fails
# the gate on the two vehicles that failure mode has actually used:
#
#   1. An OPEN entry in BUGS.md. That file is a tripwire: it must stay empty.
#      A bug found is a bug fixed (or a decision put to the human), not a row
#      in a to-do list.
#   2. A NEW deferral idiom added to PLAN.md — the prose vehicle the pattern
#      slipped through ("surfaced, not done", "deferred to a dedicated pass",
#      "gold-plating the working", …). Only lines this change ADDS are checked,
#      against a base ref, so entries that predate the rule don't trip it and
#      the changelog's legitimate uses of "deferred" (the deferred-reply
#      mechanism, e.g. `emit_deferred`) are not matched — the banned set is the
#      specific self-authorized-deferral phrasings, not the word "defer".
#
# This is a *marker* guard (like check-noops.sh): high-signal, zero false
# positives by construction. It cannot catch a deferral dressed in fresh words;
# that is what the hard rule and review are for. It catches the known vehicles
# so the documented regression cannot recur silently.
#
# Portable to bash 3.2 (macOS): no mapfile, no process-substitution required.
#
# Exit non-zero (and print each offender) if a deferral vehicle is in use.

set -euo pipefail
cd "$(dirname "$0")/.."

fail=0

# 1. BUGS.md must carry no open bug checkboxes.
if grep -nE '^[[:space:]]*-[[:space:]]*\[[[:space:]]\]' BUGS.md >/dev/null 2>&1; then
  echo "no-defer guard: BUGS.md has open bug entries — fix them, or put the"
  echo "                decision to the human. BUGS.md is a tripwire, not a backlog:"
  grep -nE '^[[:space:]]*-[[:space:]]*\[[[:space:]]\]' BUGS.md
  fail=1
fi

# 2. No new deferral idiom added to PLAN.md in this change.
base="${1:-origin/main}"
if git rev-parse --verify -q "$base" >/dev/null 2>&1; then
  # Newly-added PLAN.md lines only (strip the +++ header line).
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
