#!/usr/bin/env bash
# check-noops.sh — guard the "no silent no-ops" hard rule (AGENTS.md,
# DESIGN §2). A no-op is code that accepts a client-observable request and
# silently does nothing: a stub that returns success without acting, a
# deferred-work marker left in shipped source, an unmessaged panic that
# hides which invariant broke.
#
# This is a *marker* guard: it catches the unambiguous textual smells with
# zero false positives, so a red result always means a real regression.
# It does NOT claim to catch every logic-level no-op (a handler that drops
# a mode it parsed, an endpoint that 200s without persisting) — those are
# caught by review against the rule and by the differential/irctest suites.
# Keeping this guard high-signal is the point: a noisy guard gets muted,
# and a muted guard enforces nothing.
#
# Scope: shipped crate source only (crates/**/src). Test code is exempt —
# todo!()/panic!() are legitimate there.
#
# Portable to bash 3.2 (macOS): no mapfile, no arrays of matches. Every
# platform runs this, not just CI (DESIGN §1).
#
# Exit non-zero (and print each offender) if any banned marker appears.

set -euo pipefail
cd "$(dirname "$0")/.."

# Shipped source only: all crate *.rs, minus any tests/ subtree.
scan() { grep -rnE "$1" crates --include='*.rs' | grep -vE '/tests/' || true; }

fail=0
report() { # <label> <pattern>
	local label="$1" hits
	hits="$(scan "$2")"
	if [ -n "$hits" ]; then
		echo "no-op guard: $label"
		printf '%s\n' "$hits" | sed 's/^/  /'
		echo
		fail=1
	fi
}

# 1. Not-implemented / deferred-execution markers in shipped code.
report "todo!()/unimplemented!() in shipped source (implement or reject loudly)" \
	'\b(todo!|unimplemented!)[[:space:]]*\('

# 2. Panics with no message hide which invariant failed. Require a reason
#    string on unreachable!/panic! (unreachable!("why"), panic!("why")).
report "unmessaged unreachable!()/panic!() (state the invariant that broke)" \
	'\b(unreachable!|panic!)[[:space:]]*\([[:space:]]*\)'

# 3. Deferred-work markers do not belong in shipped source — the "why"
#    goes in a commit message, the "what remains" in PLAN.md, never a
#    rotting in-code TODO (AGENTS.md, feedback_no_phase_or_bug_refs).
report "TODO/FIXME/XXX marker in shipped source (track it in PLAN.md, not the code)" \
	'\b(TODO|FIXME|XXX)\b'

if [ "$fail" -ne 0 ]; then
	echo "no-op guard FAILED — see above. Fix the code, do not silence the guard."
	exit 1
fi
scanned="$(grep -rl '' crates --include='*.rs' | grep -vcE '/tests/')"
echo "no-op guard: clean ($scanned shipped source files scanned)"
