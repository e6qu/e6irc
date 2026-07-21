#!/usr/bin/env bash
# check-dead-code.sh — fail if the shipped artifacts contain dead code.
#
# The subtlety this guard exists for: `cargo clippy --all-targets` (what the
# normal lint job runs) compiles the test targets too, so an item used *only*
# from a `#[cfg(test)]` module or an integration test looks "used" and the
# dead_code lint stays silent. Test code keeping otherwise-unreachable code
# alive is exactly how dead code hides.
#
# So this guard compiles ONLY the production artifacts — `--lib --bins`, never
# `--all-targets` — with `cfg(test)` off. In that build, code reachable only
# from tests is unused, and rustc's own `dead_code`/`unused_*` lints fire.
# `-D warnings` turns any such finding into a failure.
#
# `--all-features` is deliberate: an item is dead only if it is unreachable in
# *every* configuration, so the maximally-enabled build is the honest one — if
# something is unused even with every feature on, it is genuinely dead.
#
# Scope/limits (stated, not hidden): rustc's dead_code analysis is per-crate
# and treats a library's `pub` items as reachable API, so a `pub` item in a lib
# crate that only integration tests call cannot be caught here — keep the lib's
# `pub` surface minimal (prefer `pub(crate)`) so this guard can see it. What it
# does catch with zero false positives: every private / `pub(crate)` fn, type,
# const, field, or import that only tests keep alive.
#
# Requires the embed-web asset dir (web/dist) to exist because `--all-features`
# turns on `embed-web`; run `pnpm -C web build` first (CI does), same as the
# clippy lint job.
#
# Portable to bash 3.2 (macOS): runs on every platform, not just CI.

set -euo pipefail
cd "$(dirname "$0")/.."

echo "dead-code guard: building production artifacts only (cfg(test) off) ..."

# No --all-targets: test targets are not compiled, so test-only usage cannot
# mask dead code. RUSTFLAGS carries -D warnings so dead_code becomes an error.
# Clippy is used (not plain check) so its unused-code lints apply too.
RUSTFLAGS="${RUSTFLAGS:-} -D warnings" \
	cargo clippy --workspace --all-features --lib --bins --quiet

echo "dead-code guard: clean (no code kept alive only by tests)"
