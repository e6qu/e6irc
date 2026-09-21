#!/usr/bin/env bash
# Portable to bash 3.2.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cd "$work"
git init -q
git config user.email test@example.test
git config user.name test
mkdir tools
cp "$root/tools/check-no-defer.sh" tools/
printf '%s\n' '# Bugs' '' '- [x] a closed entry' > BUGS.md
printf '%s\n' '# Plan' > PLAN.md
git add . && git commit -qm base
base=$(git rev-parse HEAD)

expect_fail() { # REASON [BASE]
    if tools/check-no-defer.sh "${2-$base}" >/dev/null 2>&1; then
        echo "expected no-defer failure: $1" >&2
        exit 1
    fi
    git reset --hard -q "$base"
    git clean -fdq
}

tools/check-no-defer.sh "$base" >/dev/null

printf '%s\n' '- [ ] an open entry' >> BUGS.md
expect_fail 'open BUGS.md entry'
rm BUGS.md
expect_fail 'BUGS.md deleted'
printf '%s\n' 'The cleanup is deferred to a future sweep.' >> PLAN.md
expect_fail 'deferral idiom added to PLAN.md'
# A base that does not resolve leaves the PLAN.md additions unexamined; that
# is a failed check, not a clean one. The same holds for the default base.
expect_fail 'unresolvable base ref' refs/heads/no-such-branch
if tools/check-no-defer.sh >/dev/null 2>&1; then
    echo 'expected no-defer failure: default base origin/main is absent' >&2
    exit 1
fi

printf '%s\n' 'An ordinary status line.' >> PLAN.md
tools/check-no-defer.sh "$base" >/dev/null
echo "no-defer guard contract ok"
