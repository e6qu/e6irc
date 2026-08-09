#!/usr/bin/env bash
set -euo pipefail

base=${1:?usage: check-migration-integrity.sh <base-revision>}
base=$(git merge-base HEAD "$base")

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
            if [[ -n "$last_historical" && "$before" < "$last_historical" ]]; then
                echo "error: new migration must append after $last_historical: $before" >&2
                exit 1
            fi
            ;;
    esac
done < <(git diff --name-status -M "$base" -- migrations)
