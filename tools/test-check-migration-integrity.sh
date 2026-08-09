#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git init -q
git config user.email test@example.test
git config user.name test
mkdir migrations tools
cp "$root/tools/check-migration-integrity.sh" tools/
printf '%s\n' 'CREATE TABLE one ();' > migrations/0001_one.sql
git add . && git commit -qm base
base=$(git rev-parse HEAD)

expect_fail() {
    git add -A
    if tools/check-migration-integrity.sh "$base" >/dev/null 2>&1; then
        echo "expected migration-integrity failure: $1" >&2
        exit 1
    fi
    git reset --hard -q "$base"
    git clean -fdq
}

printf '%s\n' '-- comment' >> migrations/0001_one.sql
expect_fail comment
printf '%s\n' 'ALTER TABLE one ADD COLUMN two INT;' >> migrations/0001_one.sql
expect_fail sql
rm migrations/0001_one.sql
expect_fail delete
git mv migrations/0001_one.sql migrations/0002_one.sql
expect_fail rename
printf '%s\n' 'CREATE TABLE zero ();' > migrations/0000_zero.sql
expect_fail ordering
printf '%s\n' 'CREATE TABLE two ();' > migrations/0002_two.sql
git add migrations/0002_two.sql
tools/check-migration-integrity.sh "$base"
