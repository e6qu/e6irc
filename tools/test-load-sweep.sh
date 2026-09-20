#!/usr/bin/env bash
# Portable to bash 3.2, which is the point: macOS ships it, and under `set -u`
# it treats the expansion of an empty array as an unbound variable.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/tools/load" "$work/target/release"
cp "$root/tools/load/sweep.sh" "$work/tools/load/"
printf '%s\n' '#!/bin/sh' 'printf "%s\n" "$*"' > "$work/target/release/e6irc-load"
chmod +x "$work/target/release/e6irc-load"

# `! command` is exempt from errexit, so a bare negation asserts nothing.
refuses() {
    if "$@" >/dev/null 2>&1; then
        echo "expected a refusal: $*" >&2
        exit 1
    fi
}

shells=(bash)
[[ ! -x /bin/bash ]] || shells+=(/bin/bash)
for shell in "${shells[@]}"; do
    plain=$("$shell" "$work/tools/load/sweep.sh" 127.0.0.1:6667 "1 2" 5)
    [[ "$plain" == *"--addr 127.0.0.1:6667 --clients 1 --burst 5"$'\n'* ]]
    [[ "$plain" == *"--addr 127.0.0.1:6667 --clients 2 --burst 5" ]]

    extra=$("$shell" "$work/tools/load/sweep.sh" 127.0.0.1:6667 1 5 \
        --report-dir "$work/reports" --channels 3)
    [[ "$extra" == *"--clients 1 --burst 5 --channels 3 --report-json $work/reports/1.json" ]]
    rm -r "$work/reports"

    refuses "$shell" "$work/tools/load/sweep.sh" 127.0.0.1:6667 1 5 --report-dir
    refuses "$shell" "$work/tools/load/sweep.sh" 127.0.0.1:6667 1 5 --report-json x
done
echo "load sweep contract ok"
