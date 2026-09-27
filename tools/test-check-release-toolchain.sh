#!/usr/bin/env bash
# Contract test for tools/check-release-toolchain.sh: the repository's own
# files pass, and each way of drifting from rust-toolchain.toml fails.
# Portable to bash 3.2.
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

reset() {
  rm -rf "$work/repo"
  mkdir -p "$work/repo/tools" "$work/repo/.github/workflows"
  cp "$root/tools/check-release-toolchain.sh" "$work/repo/tools/"
  cp "$root/rust-toolchain.toml" "$root/Dockerfile" "$work/repo/"
  cp "$root"/.github/workflows/*.yml "$work/repo/.github/workflows/"
}

expect_fail() { # REASON
  if "$work/repo/tools/check-release-toolchain.sh" >/dev/null 2>&1; then
    echo "expected release-toolchain failure: $1" >&2
    exit 1
  fi
  reset
}

# Replace the first line matching PATTERN (a fixed string) in FILE with LINE.
replace_first() { # FILE PATTERN LINE
  python3 - "$@" <<'EOF'
import sys
path, pattern, line = sys.argv[1:]
with open(path, encoding="utf-8") as handle:
    lines = handle.read().split("\n")
for index, text in enumerate(lines):
    if pattern in text:
        lines[index] = line
        break
else:
    sys.exit(f"{pattern!r} not found in {path}")
with open(path, "w", encoding="utf-8") as handle:
    handle.write("\n".join(lines))
EOF
}

reset
"$work/repo/tools/check-release-toolchain.sh" >/dev/null

channel=$(sed -n 's/^channel = "\(.*\)"$/\1/p' "$root/rust-toolchain.toml")
repo=$work/repo

replace_first "$repo/rust-toolchain.toml" 'channel = ' 'channel = "1.0.0"'
expect_fail 'rust-toolchain.toml moved without the rest'
replace_first "$repo/rust-toolchain.toml" 'channel = ' 'channel = "stable"'
expect_fail 'a floating channel in rust-toolchain.toml'
rm "$repo/rust-toolchain.toml"
expect_fail 'rust-toolchain.toml deleted'
replace_first "$repo/.github/workflows/ci.yml" "toolchain: $channel" '          toolchain: stable'
expect_fail 'a CI job on floating stable'
replace_first "$repo/.github/workflows/ci.yml" "toolchain: $channel" '          toolchain: 1.0.0'
expect_fail 'a CI job on another release'
replace_first "$repo/.github/workflows/release.yml" "toolchain: $channel" '          toolchain: 1.0.0'
expect_fail 'the native release on another release'
replace_first "$repo/.github/workflows/qualification.yml" "toolchain: $channel" '          toolchain: stable'
expect_fail 'the qualification runner on floating stable'
replace_first "$repo/.github/workflows/ci.yml" 'toolchain: nightly-' '          toolchain: nightly'
expect_fail 'fuzz-smoke on an unpinned nightly'
replace_first "$repo/.github/workflows/ci.yml" 'fuzz run' '            cargo +nightly-2000-01-01 fuzz run "$target" -- -max_total_time=30'
expect_fail "a cargo + in fuzz-smoke that is not the job's nightly"
replace_first "$repo/.github/workflows/ci.yml" 'cargo build --locked -p e6ircd -p e6irc-load' '      - run: cargo +nightly build --locked -p e6ircd -p e6irc-load'
expect_fail 'cargo + outside fuzz-smoke'
replace_first "$repo/.github/workflows/ci.yml" 'RUSTUP_TOOLCHAIN: nightly-' '      RUSTUP_TOOLCHAIN: nightly-2000-01-01'
expect_fail "fuzz-smoke's RUSTUP_TOOLCHAIN not its nightly"
replace_first "$repo/.github/workflows/ci.yml" 'RUSTUP_TOOLCHAIN: nightly-' ''
expect_fail "fuzz-smoke without RUSTUP_TOOLCHAIN"
replace_first "$repo/.github/workflows/ci.yml" 'CARGO_TERM_COLOR: always' '  RUSTUP_TOOLCHAIN: stable'
expect_fail 'RUSTUP_TOOLCHAIN overriding the file workflow-wide'
replace_first "$repo/Dockerfile" 'FROM rust:' 'FROM rust:1.0.0-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build'
expect_fail 'the Dockerfile on another release'
replace_first "$repo/Dockerfile" 'FROM rust:' 'FROM rust:1-bookworm@sha256:93ce27a88655056a51dbdd8f5f2d7ddc071c7b0070fb288a37b5a285fc83971e AS build'
expect_fail 'the Dockerfile on a floating tag'
replace_first "$repo/Dockerfile" '#   rust:' '#   rust:1.0.0-bookworm  resolved 2000-01-01'
expect_fail "the Dockerfile's pin comment naming another release"
replace_first "$repo/Dockerfile" 'ENV RUSTUP_AUTO_INSTALL=0' ''
expect_fail 'the Dockerfile letting rustup fetch a toolchain'
replace_first "$repo/.github/workflows/release.yml" 'cargo install cargo-auditable' '      - uses: Swatinem/rust-cache@c19371144df3bb44fab255c43d04cbc2ab54d1c4 # v2.9.1'
expect_fail 'a native release restoring a build cache'

echo "release-toolchain guard contract ok"
