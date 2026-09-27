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

# The only name sqlx runs: `<version>_<description>.sql` directly in
# migrations/. It skips anything else without a word, so a misnamed file
# (`0090-add-index.sql`, `0090_x.SQL`, `0090_x.sql.txt`) would never be
# applied; every path added under migrations/ must have this shape.
migration_name='^migrations/[0-9]+_[^/]+\.sql$'

last_historical=$(git ls-tree -r --name-only "$base" -- migrations | grep -E "$migration_name" | sort | tail -1 || true)
last=""
if [[ -n "$last_historical" ]]; then
    last=$(basename "$last_historical"); last=${last%%_*}
fi

# What this checkout changed against the base: `git diff` for tracked files
# (committed or not), and every file git does not track yet and does not
# ignore, which `git diff` never lists, as an addition. Both are captured
# before they are read, so a failing git command fails the guard instead of
# leaving nothing to check.
changes=$(git diff --name-status -M "$base" -- migrations)
untracked=$(git ls-files --others --exclude-standard -- migrations)
while IFS= read -r path; do
    if [[ -n "$path" ]]; then
        changes+=$'\n'"A"$'\t'"$path"
    fi
done <<< "$untracked"

while IFS= read -r row; do
    [[ -n "$row" ]] || continue
    IFS=$'\t' read -r status before after <<< "$row"
    case "$status" in
        M|D|T)
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
            if [[ ! "$before" =~ $migration_name ]]; then
                echo "error: $before is not named <version>_<description>.sql; sqlx would never apply it" >&2
                exit 1
            fi
            # Compared by version number, not by path: a path comparison let a
            # second migration reuse the last number with a later-sorting name.
            # Both numbers are all digits here (the name matched above), so the
            # comparison cannot fail on a malformed operand and read as false.
            if [[ -n "$last" ]]; then
                new=$(basename "$before"); new=${new%%_*}
                if ! (( 10#$new > 10#$last )); then
                    echo "error: new migration must use a version above $last_historical: $before" >&2
                    exit 1
                fi
            fi
            ;;
        *)
            echo "error: unexpected change '$status' to $before" >&2
            exit 1
            ;;
    esac
done <<< "$changes"
