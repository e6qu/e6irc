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
cp "$root/BUGS.md" BUGS.md
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
printf '%s\n' '- [x] a closed entry kept for the record' >> BUGS.md
expect_fail 'closed BUGS.md entry'
printf '%s\n' '' 'The parser drops a tag; revisit.' >> BUGS.md
expect_fail 'prose added to BUGS.md'
rm BUGS.md
expect_fail 'BUGS.md deleted'
printf '%s\n' 'The cleanup is deferred to a future sweep.' >> PLAN.md
expect_fail 'deferral idiom added to PLAN.md'
printf '%s\n' 'The rename is deferred to a later pass.' >> PLAN.md
expect_fail 'deferred to a later pass added to PLAN.md'
# Ordinary rewordings of the same move, each of which once passed.
for phrase in \
    'Deferred to a follow-up PR.' \
    'Left for a later change.' \
    'Out of scope for this sweep; revisit later.' \
    'Surfaced, not fixed.' \
    'The tidy-up is deferred to the next sweep.' \
    'Parked for a separate commit.' \
    'Worth a follow-up issue.' \
    'Revisit this once the parser lands.' \
    'That belongs in a future PR.' \
    'Will fix in a follow-up.' \
    'The cap is deferred to later.' \
    'The cleanup is left for later.' \
    'Deferred to a future release.' \
    'The race is to be addressed later.' \
    'The leak is not fixed in this PR.' \
    'Tracked separately.' \
    'Postponed until the next release.' \
    'Retry support is left as future work.' \
    'Future work: support X.' \
    'We postpone the migration.' \
    'Not yet handled in this change.'; do
    printf '%s\n' "$phrase" >> PLAN.md
    expect_fail "\"$phrase\" added to PLAN.md"
done
# A file git does not track yet is added lines too: `git diff` alone never
# shows it, so a note written into a new, unstaged file once passed unread.
for file in NOTES.md docs/new-guide.md 'docs/with space.md'; do
    mkdir -p "$(dirname "$file")"
    printf '%s\n' 'An ordinary line.' 'The retry cap is left for later.' > "$file"
    expect_fail "deferral note in the untracked $file"
done
# An untracked file the repository ignores is not part of the change.
printf '%s\n' 'scratch/' > .gitignore
git add .gitignore && git commit -qm ignore
ignored_base=$(git rev-parse HEAD)
mkdir scratch
printf '%s\n' 'The retry cap is left for later.' > scratch/notes.md
tools/check-no-defer.sh "$ignored_base" >/dev/null
rm -rf scratch
git reset --hard -q "$base"
git clean -fdq
# Every file's added lines are read, not PLAN.md's alone.
for file in DESIGN.md README.md docs/guide.md src/lib.rs; do
    mkdir -p "$(dirname "$file")"
    printf '%s\n' '// The retry cap is deferred to a follow-up change.' >> "$file"
    git add "$file"
    expect_fail "deferral note added to $file"
done
# The rule's own statement quotes the idioms it bans.
printf '%s\n' 'It has shown up as "surfaced, not done" and "deferred to a dedicated pass".' > AGENTS.md
git add AGENTS.md
tools/check-no-defer.sh "$base" >/dev/null
git reset --hard -q "$base"
git clean -fdq
# Plain technical prose that shares a word is not a deferral.
printf '%s\n' 'An error is surfaced, not silently dropped.' \
    'The reply is deferred until the database answers.' \
    'A history request on an incomplete ring must defer to the database.' \
    'Output is held behind a deferred reply; DeferredReply::release frees it.' \
    'The capture counts its deferrals.' \
    'Nothing is held for playback; a follow-up message is sent on attach.' \
    'The future is cancelled when the peer disconnects.' >> DESIGN.md
git add DESIGN.md
tools/check-no-defer.sh "$base" >/dev/null
git reset --hard -q "$base"
git clean -fdq
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
