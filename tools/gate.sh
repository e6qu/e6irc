#!/usr/bin/env bash
# The repository's guard gate: every structural guard and every guard's own
# contract test, in one list. CI's `lint` job runs exactly this script, and
# AGENTS.md's checklist points here instead of keeping a second copy of the
# list, so the two cannot drift. What it does not cover (builds, clippy in each
# feature configuration, the test suites, the dead-code build, the fuzz
# type-check) is on that checklist and in CI's other steps and jobs.
#
#   tools/gate.sh [--base REV] [--skip-cargo-deny]
#
#   --base REV         the revision this change is measured against: the
#                      migration-integrity and no-deferral guards read what it
#                      added. Default origin/main; one that does not resolve
#                      fails those two guards, never skips them.
#   --skip-cargo-deny  leave out `cargo deny check` for the workspace and for
#                      fuzz/Cargo.toml. CI passes it because its `deny` job
#                      runs both with the cargo-deny action; anywhere else the
#                      gate runs them and needs `cargo-deny` installed.
#
# Every step runs even after an earlier one failed; the summary names each
# failed step and each skipped one, and the exit status is 1 if any failed.
# Portable to bash 3.2.
set -uo pipefail

cd "$(dirname "$0")/.."

base=origin/main
cargo_deny=1
while [ "$#" -gt 0 ]; do
  case "$1" in
    --base)
      [ "$#" -ge 2 ] || { echo "gate: --base needs a revision" >&2; exit 2; }
      base=$2
      shift 2
      ;;
    --skip-cargo-deny)
      cargo_deny=0
      shift
      ;;
    *)
      echo "usage: $0 [--base REV] [--skip-cargo-deny]" >&2
      exit 2
      ;;
  esac
done

failed=()
skipped=()
steps=0

step() { # NAME COMMAND...
  local name=$1
  shift
  steps=$((steps + 1))
  echo "::group::gate: $name"
  if "$@"; then
    echo "::endgroup::"
  else
    echo "::endgroup::"
    echo "gate: FAILED: $name" >&2
    failed+=("$name")
  fi
}

# One script per invocation: `-n` parses only its first operand, and the rest
# would become that script's positional parameters, unread.
shell_syntax() {
  local script status=0
  for script in tools/*.sh tools/*/*.sh vendor/tests/irctest/run.sh; do
    case "$(head -n 1 "$script")" in
      '#!/bin/sh'*) sh -n "$script" || status=1 ;;
      *) bash -n "$script" || status=1 ;;
    esac
  done
  return "$status"
}

# fuzz/ is outside the workspace, so neither `cargo fmt --all` nor any
# workspace step reaches its targets; native.rs is included by path.
formatting() {
  cargo fmt --all --check &&
    rustfmt --edition 2024 --check crates/e6irc-qualification/tests/support/native.rs &&
    rustfmt --edition 2024 --check fuzz/fuzz_targets/*.rs
}

# fuzz/Cargo.lock resolves on its own; keep it on the workspace's versions, and
# current for fuzz/Cargo.toml (`cargo fuzz` has no `--locked`, and would
# re-resolve a stale lock without a word).
fuzz_lock() {
  python3 tools/check-fuzz-lock.py &&
    cargo metadata --locked --format-version 1 --manifest-path fuzz/Cargo.toml >/dev/null
}

# fuzz/ is a package of its own with its own lock, so the workspace check never
# sees it; cargo-deny finds the repository's deny.toml from either manifest.
cargo_deny_check() {
  cargo deny check && cargo deny --manifest-path fuzz/Cargo.toml check
}

step "systemd unit" tools/check-systemd-unit.sh
# Every build resolves from Cargo.lock exactly, and one Rust toolchain builds
# everything.
step "locked builds" tools/check-locked-builds.sh
step "release toolchain" tools/check-release-toolchain.sh
step "shell syntax" shell_syntax
step "formatting" formatting
step "fuzz lock" fuzz_lock
# Every pulled image is pinned by one digest.
step "image pins" python3 tools/check-image-pins.py
step "migration integrity against $base" tools/check-migration-integrity.sh "$base"
# AGENTS.md's No-Deferral Rule: BUGS.md stays empty, and no file-it-for-later
# idiom is added to any file.
step "no deferral against $base" tools/check-no-defer.sh "$base"
# DESIGN §2: no deferred-work markers or unmessaged panics in shipped source.
step "no-ops" tools/check-noops.sh
# The cross-crate case the compiler cannot see: a `pub` item referenced only by
# an integration test, a fuzz target, or inline test-only code.
step "dead public items" tools/check-dead-pub.sh
step "duplication" tools/check-duplication.sh
# Every user-facing outcome carries one complete contract row.
step "journeys" python3 tools/check-journeys.py
# Every abbreviation in the docs and code comments is defined in
# docs/terminology.md or spelled out where it is used.
step "terminology" python3 tools/check-terminology.py
step "client capabilities" python3 tools/check-client-capabilities.py
# Every data table keeps an accessible caption, every navigation landmark a name.
step "template accessibility" python3 tools/check-template-accessibility.py
# Console forms may not bypass the public API.
step "API-first inventory" python3 tools/check-api-first-inventory.py

# The guards' own contract tests, and the other tools' self-tests. Every
# tools/test-check-* is found by name, so a new guard's test cannot be left out.
for test in tools/test-check-*; do
  case "$test" in
    *.py) step "${test#tools/}" python3 "$test" ;;
    *) step "${test#tools/}" "$test" ;;
  esac
done
step "backup and restore" tools/test-backup-restore.sh
step "load qualification arguments" tools/test-load-qualification-arguments.sh
step "load sweep" tools/test-load-sweep.sh
step "qualification evidence" tools/test-qualification.sh
step "native release packaging" python3 tools/test-native-release-package.py
step "irctest skip list" python3 vendor/tests/irctest/test_check_skips.py

if [ "$cargo_deny" -eq 1 ]; then
  step "cargo deny (workspace and fuzz/)" cargo_deny_check
else
  skipped+=("cargo deny (workspace and fuzz/): --skip-cargo-deny (CI's deny job runs it)")
fi

echo
echo "gate: $steps steps, ${#failed[@]} failed, ${#skipped[@]} skipped"
for name in ${skipped[@]+"${skipped[@]}"}; do
  echo "gate: skipped: $name"
done
if [ "${#failed[@]}" -gt 0 ]; then
  for name in "${failed[@]}"; do
    echo "gate: failed: $name" >&2
  done
  exit 1
fi
echo "gate: clean"
