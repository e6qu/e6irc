#!/usr/bin/env bash
# Every build that produces something shipped, tested, or copied by an operator
# resolves dependencies from Cargo.lock exactly. Without `--locked` a build
# whose lock is stale silently re-resolves to whatever the registry has today,
# so the binary is not the one the lock, the SBOM, and cargo-deny describe.
#
# Checked: the Dockerfile, the workflows, the scripts under tools/, and the
# operator-facing documents that print a build command. A `cargo build` (or
# `cargo auditable build`) whose line lacks `--locked` fails the gate, named by
# file and line.
set -euo pipefail

cd "$(dirname "$0")/.."

files=(Dockerfile README.md deploy/README.md)
while IFS= read -r file; do
  files+=("$file")
done < <(find .github/workflows -name '*.yml' -type f; find tools -type f \( -name '*.sh' -o -name '*.md' -o -name '*.py' \) ! -path '*/__pycache__/*')

unlocked=0
for file in "${files[@]}"; do
  [ -f "$file" ] || continue
  [ "$file" = tools/check-locked-builds.sh ] && continue
  while IFS=: read -r line text; do
    case "$text" in
      *--locked*) ;;
      *)
        echo "$file:$line: cargo build without --locked: ${text#"${text%%[![:space:]]*}"}" >&2
        unlocked=1
        ;;
    esac
  done < <(grep -nE 'cargo( auditable)? build' "$file" || true)
done

if [ "$unlocked" -ne 0 ]; then
  echo "every cargo build must pass --locked so it builds exactly what Cargo.lock states" >&2
  exit 1
fi
