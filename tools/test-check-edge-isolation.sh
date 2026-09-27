#!/usr/bin/env bash
# Contract for tools/check-edge-isolation.sh, run against a scratch workspace of
# path crates (no registry needed): a forbidden crate anywhere in e6irc-edge's
# graph fails the guard by name — directly, through another crate, as a
# dev-dependency, on another platform, or behind a feature — and a clean graph
# passes. A workspace without e6irc-edge fails rather than checking nothing.
# Portable to bash 3.2.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

crate() { # NAME [DEPENDENCY SECTION...]
    local name=$1
    shift
    mkdir -p "$work/crates/$name/src"
    : > "$work/crates/$name/src/lib.rs"
    {
        printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2024"\n\n' "$name"
        printf '%s\n' "$@"
    } > "$work/crates/$name/Cargo.toml"
}

# The edge with the given extra manifest lines, next to every crate a case may
# reach.
reset() { # [manifest line...]
    rm -rf "${work:?}"/*
    mkdir -p "$work/tools"
    cp "$root/tools/check-edge-isolation.sh" "$work/tools/"
    printf '[workspace]\nresolver = "3"\nmembers = ["crates/*"]\n' > "$work/Cargo.toml"
    crate harmless
    for name in sqlx sqlx-core tokio-postgres e6ircd reqwest; do
        crate "$name"
    done
    crate middle '[dependencies]' 'sqlx-core = { path = "../sqlx-core" }'
    crate e6irc-edge '[dependencies]' 'harmless = { path = "../harmless" }' "$@"
    (cd "$work" && cargo generate-lockfile --offline --quiet)
}

expect_clean() { # REASON
    if ! (cd "$work" && tools/check-edge-isolation.sh) >/dev/null 2>&1; then
        echo "expected the edge isolation guard to pass: $1" >&2
        (cd "$work" && tools/check-edge-isolation.sh) >&2 || true
        exit 1
    fi
}

expect_fail() { # crate reason
    if out=$(cd "$work" && tools/check-edge-isolation.sh 2>&1); then
        echo "expected the edge isolation guard to fail: $2" >&2
        exit 1
    fi
    case "$out" in
        *"  $1, reached by:"*) ;;
        *)
            echo "the edge isolation guard failed without naming $1: $2" >&2
            echo "$out" >&2
            exit 1
            ;;
    esac
}

reset
expect_clean 'a graph of harmless crates'

reset 'sqlx = { path = "../sqlx" }'
expect_fail sqlx 'a direct dependency on sqlx'

reset 'middle = { path = "../middle" }'
expect_fail sqlx-core 'sqlx reached through another crate'

reset '[dev-dependencies]' 'e6ircd = { path = "../e6ircd" }'
expect_fail e6ircd 'the core as a dev-dependency'

reset "[target.'cfg(windows)'.dependencies]" 'reqwest = { path = "../reqwest" }'
expect_fail reqwest 'a dependency on another platform'

reset 'tokio-postgres = { path = "../tokio-postgres", optional = true }' \
    '[features]' 'database = ["dep:tokio-postgres"]'
expect_fail tokio-postgres 'a dependency behind a feature'

reset
rm -rf "$work/crates/e6irc-edge"
(cd "$work" && cargo generate-lockfile --offline --quiet)
if (cd "$work" && tools/check-edge-isolation.sh) >/dev/null 2>&1; then
    echo "expected the edge isolation guard to fail without an e6irc-edge crate" >&2
    exit 1
fi

echo "edge isolation guard contract ok"
