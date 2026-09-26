#!/usr/bin/env bash
# Guard no-silent-no-ops in shipped source. Portable to bash 3.2.
#
# Rust under crates/ (integration tests excluded) is scanned for todo!(),
# unimplemented!() and unmessaged panics; every shipped source — that Rust,
# the web client (web/src), the console's script and the server-rendered
# templates — for deferred-work markers. An empty message ("") is no message.
# Every #[should_panic] test, integration tests included, must name the panic
# it expects: a bare one passes on any panic, an unrelated bug's included.
# tools/test-check-noops.sh holds the contract.

set -euo pipefail
cd "$(dirname "$0")/.."

rust() { grep -rnE "$1" crates --include='*.rs' | grep -vE '/tests/' || true; }
all_rust() { grep -rnE "$1" crates --include='*.rs' || true; }
shipped() {
	{
		rust "$1"
		grep -rnE "$1" web/src crates/e6ircd/assets crates/e6ircd/templates || true
	}
}

fail=0
report() { # <label> <scanner> <pattern>
	local label="$1" hits
	hits="$("$2" "$3")"
	if [ -n "$hits" ]; then
		echo "no-op guard: $label"
		printf '%s\n' "$hits" | sed 's/^/  /'
		echo
		fail=1
	fi
}

report "todo!()/unimplemented!() in shipped source (implement or reject loudly)" \
	rust '\b(todo!|unimplemented!)[[:space:]]*\('

report "unmessaged unreachable!()/panic!()/expect() (state the invariant that broke)" \
	rust '\b(unreachable!|panic!)[[:space:]]*\([[:space:]]*(""[[:space:]]*)?\)|\.expect\([[:space:]]*""[[:space:]]*\)'

report "TODO/FIXME/XXX marker in shipped source (fix it or ask the human)" \
	shipped '\b(TODO|FIXME|XXX)\b'

report "#[should_panic] without expected = \"…\" (it would pass on any panic)" \
	all_rust '#\[should_panic[[:space:]]*\]'

if [ "$fail" -ne 0 ]; then
	echo "no-op guard FAILED — see above. Fix the code, do not silence the guard."
	exit 1
fi
scanned="$( {
	grep -rl '' crates --include='*.rs' | grep -vE '/tests/'
	grep -rl '' web/src crates/e6ircd/assets crates/e6ircd/templates
} | wc -l | tr -d ' ')"
echo "no-op guard: clean ($scanned shipped source files scanned)"
