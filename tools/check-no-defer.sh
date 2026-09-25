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

# Check only newly added lines, in every file: a deferral note reads the same
# in PLAN.md, DESIGN.md, a README, docs/** or a code comment. Exempt are the
# rule's own statement (AGENTS.md, which quotes the idioms it bans) and this
# guard and its contract test, which must spell them out.
base="${1:-origin/main}"
if ! git rev-parse --verify -q "$base^{commit}" >/dev/null; then
  echo "no-defer guard: base ref '$base' does not resolve, so this change's added"
  echo "                lines cannot be examined. Fetch it, or pass one that"
  echo "                exists (e.g. tools/check-no-defer.sh main)."
  exit 1
fi
added="$(git diff --no-color --unified=0 "$base" -- . \
  ':(exclude)AGENTS.md' ':(exclude)tools/check-no-defer.sh' \
  ':(exclude)tools/test-check-no-defer.sh' |
  awk '/^\+\+\+ /{file=substr($0,7); next} /^\+/{print file ": " substr($0,2)}' || true)"
# What the rest of the work is put off to.
later='(dedicated|future|later|next|separate|subsequent|follow-?up) '
unit='(pass|sweep|pr|pull request|change|commit|round|iteration|follow-?up)'
banned="surfaced,? (but )?not (yet )?(done|changed|fixed|addressed|handled|implemented|resolved|acted on)"
banned="$banned|defer(s|red|ring)? ((it|this|that|them|these|those) )?(to|until|for) (a|an|the) ($later)*$unit"
banned="$banned|(left|noted|parked|kept|saved|filed|punted) ((it|this|that) )?(for|to|until) (a|an|the) ($later)*$unit"
banned="$banned|(dedicated|future|later|separate|subsequent|follow-?up) (pass|sweep|pr|pull request)([^a-z]|$)"
banned="$banned|next (sweep|pr|pull request)([^a-z]|$)"
banned="$banned|follow-?up (pr|pull request|change|commit|sweep|pass|task|ticket|issue)"
banned="$banned|revisit(ed)? ((it|this|that) )?(later|when|once|after|in a)"
banned="$banned|out of scope for this (change|sweep|pr|pull request|pass|review)"
banned="$banned|considered non-change|gold-plat"
hits="$(printf '%s\n' "$added" | grep -iE "$banned" || true)"
if [ -n "$hits" ]; then
  echo "no-defer guard: this change adds a deferral idiom. Address the item, or"
  echo "                escalate it to the human as an explicit decision — do not"
  echo "                file it as done-later:"
  printf '%s\n' "$hits"
  fail=1
fi

if [ "$fail" -eq 0 ]; then
  echo "no-defer guard: clean (no deferral vehicle in use)"
fi
exit "$fail"
