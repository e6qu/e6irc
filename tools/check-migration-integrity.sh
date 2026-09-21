#!/usr/bin/env bash
set -euo pipefail

base=${1:?usage: check-migration-integrity.sh <base-revision>}
# Pull requests use a shallow checkout.  A depth-one base fetch has no merge
# base unless it is HEAD's direct parent, but `git diff <base>` still compares
# the complete base tree correctly.
base=$(git merge-base HEAD "$base" 2>/dev/null || printf '%s\n' "$base")
# A base that does not resolve would make every diff below empty and the guard
# pass having checked nothing.
git rev-parse --verify -q "$base^{commit}" >/dev/null || {
    echo "error: base revision '$base' does not resolve" >&2
    exit 1
}

last_historical=$(git ls-tree -r --name-only "$base" -- migrations | grep -E '^migrations/[0-9]+_.+\.sql$' | sort | tail -1 || true)

while IFS= read -r row; do
    IFS=$'\t' read -r status before after <<< "$row"
    case "$status" in
        M|D)
            if git cat-file -e "$base:$before" 2>/dev/null; then
                if [[ "$status" == M ]]; then
                    changed=$(git log -1 --format=%H "$base" -- "$before")
                    if git cat-file -e "$changed^:$before" 2>/dev/null; then
                        expected=$(git show "$changed^:$before" | shasum -a 256 | awk '{print $1}')
                        actual=$(shasum -a 256 "$before" | awk '{print $1}')
                        if [[ "$actual" == "$expected" ]]; then
                            continue
                        fi
                    fi
                fi
                echo "error: applied migration is immutable: $before" >&2
                exit 1
            fi
            ;;
        R*)
            echo "error: applied migration cannot be renamed: $before" >&2
            exit 1
            ;;
        A)
            # Compared by version number, not by path: a path comparison let a
            # second migration reuse the last number with a later-sorting name.
            if [[ -n "$last_historical" ]]; then
                new=$(basename "$before"); new=${new%%_*}
                last=$(basename "$last_historical"); last=${last%%_*}
                if (( 10#$new <= 10#$last )); then
                    echo "error: new migration must use a version above $last_historical: $before" >&2
                    exit 1
                fi
            fi
            ;;
    esac
done < <(git diff --name-status -M "$base" -- migrations)
