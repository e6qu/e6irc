#!/usr/bin/env bash
# Contract for tools/check-locked-builds.sh: every command shape that resolves
# and compiles without `--locked`, in every file it covers, fails the gate by
# name; `--locked`, comments and coverage reports pass. Portable to bash 3.2.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

reset() {
    rm -rf "${work:?}"/*
    mkdir -p "$work/tools" "$work/.github/workflows" "$work/docs/journeys" \
        "$work/deploy" "$work/vendor/tests/oracle"
    cp "$root/tools/check-locked-builds.sh" "$work/tools/"
    for file in Dockerfile README.md AGENTS.md DESIGN.md PLAN.md deploy/README.md \
        docs/guide.md vendor/tests/oracle/README.md; do
        printf '%s\n' 'cargo build --locked -p e6ircd' > "$work/$file"
    done
    printf '%s\n' '      - run: cargo test --locked --workspace' \
        '      # cargo build in a comment compiles nothing' \
        '      - run: cargo llvm-cov report --lcov' > "$work/.github/workflows/ci.yml"
}

expect_clean() { # REASON
    if ! (cd "$work" && tools/check-locked-builds.sh) >/dev/null 2>&1; then
        echo "expected the --locked guard to pass: $1" >&2
        (cd "$work" && tools/check-locked-builds.sh) >&2 || true
        exit 1
    fi
    reset
}

expect_fail() { # FILE REASON
    if out=$(cd "$work" && tools/check-locked-builds.sh 2>&1); then
        echo "expected the --locked guard to fail: $2" >&2
        exit 1
    fi
    case "$out" in
        *"$1:"*) ;;
        *)
            echo "the --locked guard failed without naming $1: $2" >&2
            echo "$out" >&2
            exit 1
            ;;
    esac
    reset
}

reset
expect_clean 'baseline'

for command in 'cargo build -p e6ircd' 'cargo test --workspace' 'cargo clippy --all-targets' \
    'cargo check --manifest-path fuzz/Cargo.toml' 'cargo run -p e6irc-cli' \
    'cargo auditable build --release' 'cargo llvm-cov --lcov' 'cargo +nightly build' \
    'RUSTFLAGS="--cfg fuzzing" cargo +nightly-2026-07-23 check --bins'; do
    printf '%s\n' "      - run: $command" >> "$work/.github/workflows/ci.yml"
    expect_fail .github/workflows/ci.yml "$command"
done

for file in AGENTS.md DESIGN.md PLAN.md README.md deploy/README.md docs/guide.md \
    vendor/tests/oracle/README.md Dockerfile; do
    printf '%s\n' 'cargo test -p e6ircd --features matrix' >> "$work/$file"
    expect_fail "$file" "an unlocked command in $file"
done

printf '%s\n' 'cargo +nightly-2026-07-23 build --locked' 'cargo checkout is not a command' \
    'cargo run-script is another tool' >> "$work/docs/guide.md"
expect_clean '--locked with a toolchain, and words that only start like a command'

rm "$work/PLAN.md"
expect_fail PLAN.md 'a listed file that is gone'

echo "--locked guard contract ok"
