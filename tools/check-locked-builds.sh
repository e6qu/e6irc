#!/usr/bin/env bash
# Every build that produces something shipped, tested, linted, or copied by an
# operator resolves dependencies from Cargo.lock exactly. Without `--locked` a build
# whose lock is stale silently re-resolves to whatever the registry has today,
# so the binary is not the one the lock, the SBOM, and cargo-deny describe.
#
# Checked: the Dockerfile, the workflows, the scripts under tools/, and every
# document that prints a build command (the READMEs, AGENTS.md, DESIGN.md,
# PLAN.md, and the Markdown under docs/, deploy/ and vendor/). A `cargo build`,
# `cargo auditable build`, `cargo test`, `cargo clippy`, `cargo check`,
# `cargo run`, or `cargo llvm-cov` (each resolves and compiles), also when a
# toolchain is named (`cargo +nightly build`), whose line lacks `--locked`
# fails the gate, named by file and line. A comment line and `cargo llvm-cov
# report` (which only reads coverage already collected) compile nothing.
# `cargo fuzz` takes no `--locked`: CI runs `cargo metadata --locked` on the
# fuzz manifest before building it instead.
set -euo pipefail

cd "$(dirname "$0")/.."

files=(Dockerfile README.md AGENTS.md DESIGN.md PLAN.md)
while IFS= read -r file; do
  files+=("$file")
done < <(find .github/workflows -name '*.yml' -type f
  find tools -type f \( -name '*.sh' -o -name '*.md' -o -name '*.py' \) ! -path '*/__pycache__/*'
  find docs deploy vendor -type f -name '*.md')

unlocked=0
for file in "${files[@]}"; do
  # The named files are listed by hand; one that moved or was renamed would
  # otherwise drop out of the check without a word.
  if [ ! -f "$file" ]; then
    echo "$file: listed for the --locked check but not found; update this script" >&2
    unlocked=1
    continue
  fi
  # The guard and its contract test spell out the commands they refuse.
  case "$file" in tools/check-locked-builds.sh | tools/test-check-locked-builds.sh) continue ;; esac
  while IFS=: read -r line text; do
    case "$text" in
      *--locked*) ;;
      *)
        echo "$file:$line: cargo without --locked: ${text#"${text%%[![:space:]]*}"}" >&2
        unlocked=1
        ;;
    esac
  done < <(grep -nE 'cargo( \+[^ ]+)? (auditable build|build|test|clippy|check|run|llvm-cov)([^a-z-]|$)' "$file" \
    | grep -vE '^[0-9]+:[[:space:]]*#|cargo llvm-cov report' || true)
done

if [ "$unlocked" -ne 0 ]; then
  echo "every cargo build, test, clippy, check, run, and llvm-cov must pass --locked so it builds exactly what Cargo.lock states" >&2
  exit 1
fi
