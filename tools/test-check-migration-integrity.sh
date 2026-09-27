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

# Checks the working tree as is: a file created and never added is untracked.
expect_fail_as_is() {
    if tools/check-migration-integrity.sh "$base" >/dev/null 2>&1; then
        echo "expected migration-integrity failure: $1" >&2
        exit 1
    fi
    git reset --hard -q "$base"
    git clean -fdq
}

expect_fail() {
    git add -A
    expect_fail_as_is "$1"
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
# The same number as the last applied migration, under a later-sorting name.
printf '%s\n' 'CREATE TABLE dup ();' > migrations/0001_zzz_duplicate.sql
expect_fail duplicate-number
# sqlx runs only `<version>_<description>.sql` directly in migrations/ and
# skips any other name silently; each once passed, its number read as an
# arithmetic error that evaluated false.
for name in 0090-add-index.sql 0090_x.SQL 0090_x.sql.txt 0090.sql x_0090.sql \
    0090_.sql sub/0090_x.sql 'v0090_x.sql' '0090 x.sql'; do
    mkdir -p "$(dirname "migrations/$name")"
    printf '%s\n' 'CREATE TABLE misnamed ();' > "migrations/$name"
    expect_fail "misnamed $name"
    mkdir -p "$(dirname "migrations/$name")"
    printf '%s\n' 'CREATE TABLE misnamed ();' > "migrations/$name"
    expect_fail_as_is "untracked misnamed $name"
done
# A file never added is still part of the change `git diff` does not list.
printf '%s\n' 'CREATE TABLE dup ();' > migrations/0001_zzz_duplicate.sql
expect_fail_as_is untracked-duplicate-number
printf '%s\n' 'CREATE TABLE zero ();' > migrations/0000_zero.sql
expect_fail_as_is untracked-ordering
# An ignored file is not part of the change.
printf '%s\n' 'migrations/*.bak' > .gitignore
git add .gitignore && git commit -qm ignore
ignored_base=$(git rev-parse HEAD)
printf '%s\n' 'scratch' > migrations/0001_one.sql.bak
tools/check-migration-integrity.sh "$ignored_base"
rm migrations/0001_one.sql.bak
git reset --hard -q "$base"
git clean -fdq
# A well-named untracked migration above the last is clean.
printf '%s\n' 'CREATE TABLE two ();' > migrations/0002_two.sql
tools/check-migration-integrity.sh "$base"
git clean -fdq
# A base that does not resolve is a failure, not a clean report.
if tools/check-migration-integrity.sh no-such-ref-xyz >/dev/null 2>&1; then
    echo "expected migration-integrity failure: unresolvable base" >&2
    exit 1
fi
printf '%s\n' 'CREATE TABLE two ();' > migrations/0002_two.sql
git add migrations/0002_two.sql
tools/check-migration-integrity.sh "$base"
echo "migration-integrity guard contract ok"
