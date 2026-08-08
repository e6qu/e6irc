#!/usr/bin/env bash
# Guard no-silent-no-ops in shipped Rust source. Portable to bash 3.2.

set -euo pipefail
cd "$(dirname "$0")/.."

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

report "todo!()/unimplemented!() in shipped source (implement or reject loudly)" \
	'\b(todo!|unimplemented!)[[:space:]]*\('

report "unmessaged unreachable!()/panic!() (state the invariant that broke)" \
	'\b(unreachable!|panic!)[[:space:]]*\([[:space:]]*\)'

report "TODO/FIXME/XXX marker in shipped source (fix it or ask the human)" \
	'\b(TODO|FIXME|XXX)\b'

if [ "$fail" -ne 0 ]; then
	echo "no-op guard FAILED — see above. Fix the code, do not silence the guard."
	exit 1
fi
scanned="$(grep -rl '' crates --include='*.rs' | grep -vcE '/tests/')"
echo "no-op guard: clean ($scanned shipped source files scanned)"
