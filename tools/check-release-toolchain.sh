#!/usr/bin/env bash
# One Rust toolchain: rust-toolchain.toml's `channel`. Everything that compiles
# this repository must name that release and no other, so a new Rust release
# (or a moved `stable`) cannot give CI, the native release archives and the
# container image three different compilers under one tag:
#   - the Dockerfile's build stage is `FROM rust:<channel>-bookworm@sha256:…`
#     and records that release in its pin comment;
#   - every `toolchain:` input in .github/workflows names the channel, except
#     CI's `fuzz-smoke` job, which needs a pinned `nightly-YYYY-MM-DD` for
#     cargo-fuzz's sanitizer flags, and whose every `cargo +…` names that
#     nightly;
#   - no workflow runs `cargo +<toolchain>` outside `fuzz-smoke`, or asks for a
#     floating `stable`/`beta`/`nightly`;
#   - the native release jobs restore no build cache.
# Portable to bash 3.2.
set -euo pipefail

cd "$(dirname "$0")/.."

fail=0
problem() {
  echo "release-toolchain guard: $*" >&2
  fail=1
}

[ -f rust-toolchain.toml ] || { echo "release-toolchain guard: rust-toolchain.toml is missing" >&2; exit 1; }
channel="$(sed -n 's/^channel = "\(.*\)"$/\1/p' rust-toolchain.toml)"
if ! printf '%s\n' "$channel" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$'; then
  echo "release-toolchain guard: rust-toolchain.toml's channel '${channel}' is not an exact X.Y.Z release" >&2
  exit 1
fi

# The Dockerfile's Rust build stage, by tag, and the version its pin comment records.
image_versions="$(sed -n 's/^FROM rust:\([^@ ]*\)-bookworm@sha256:[0-9a-f]\{64\} .*/\1/p' Dockerfile | sort -u)"
if [ "$image_versions" != "$channel" ]; then
  problem "the Dockerfile builds FROM rust:'${image_versions:-none}'-bookworm, not rust:$channel-bookworm (rust-toolchain.toml)"
fi
if ! grep -Eq "^#   rust:${channel//./\\.}-bookworm " Dockerfile; then
  problem "the Dockerfile's pin comment does not record rust:$channel-bookworm"
fi
if grep -q 'rust-toolchain.toml' Dockerfile && grep -q '^ENV RUSTUP_AUTO_INSTALL=0$' Dockerfile; then
  :
else
  problem "the Dockerfile must check its compiler against rust-toolchain.toml with RUSTUP_AUTO_INSTALL=0"
fi

# FILE<TAB>JOB<TAB>LINE for every line of each workflow, JOB being the job the
# line sits in (empty outside `jobs:`).
workflow_lines() {
  awk '
    /^jobs:/ { in_jobs = 1; job = ""; next }
    /^[^ #]/ { in_jobs = 0; job = "" }
    in_jobs && /^  [A-Za-z0-9_-]+:[ ]*$/ { job = $1; sub(/:$/, "", job) }
    { print FILENAME "\t" job "\t" $0 }
  ' .github/workflows/*.yml
}

fuzz_nightly=""
fuzz_pluses=""
while IFS=$'\t' read -r file job line; do
  case "$line" in
    *'toolchain:'*)
      value="$(printf '%s\n' "$line" | sed -n 's/^ *toolchain: *\([^ #]*\).*$/\1/p')"
      [ -n "$value" ] || continue
      if [ "$job" = fuzz-smoke ] && [ "$file" = .github/workflows/ci.yml ]; then
        if printf '%s\n' "$value" | grep -Eq '^nightly-[0-9]{4}-[0-9]{2}-[0-9]{2}$'; then
          fuzz_nightly="$value"
        else
          problem "$file job $job: toolchain '$value' is not a pinned nightly-YYYY-MM-DD"
        fi
      elif [ "$value" != "$channel" ]; then
        problem "$file job ${job:-?}: toolchain '$value' is not rust-toolchain.toml's $channel"
      fi
      ;;
  esac
  case "$line" in
    *'cargo +'*)
      plus="$(printf '%s\n' "$line" | sed -n 's/.*cargo +\([^ ]*\).*/\1/p')"
      if [ "$job" != fuzz-smoke ] || [ "$file" != .github/workflows/ci.yml ]; then
        problem "$file job ${job:-?}: 'cargo +$plus' bypasses rust-toolchain.toml"
      else
        fuzz_pluses="$fuzz_pluses $plus"
      fi
      ;;
  esac
done < <(workflow_lines)

if [ -z "$fuzz_nightly" ]; then
  problem "ci.yml's fuzz-smoke job names no pinned nightly toolchain"
else
  for plus in $fuzz_pluses; do
    [ "$plus" = "$fuzz_nightly" ] || problem "ci.yml job fuzz-smoke: 'cargo +$plus' is not the job's toolchain $fuzz_nightly"
  done
fi

if grep -Eq '^ *(toolchain: *|rustup (default|override set) +)(stable|beta|nightly)( |$)' .github/workflows/*.yml; then
  problem "a workflow asks for a floating stable/beta/nightly toolchain"
fi

if sed -n '/native-build:/,/^  [a-z-]*:$/p' .github/workflows/release.yml | grep -q 'rust-cache'; then
  problem "release.yml native builds must not restore a build cache"
fi

if [ "$fail" -eq 0 ]; then
  echo "release-toolchain guard: clean (Rust $channel everywhere; fuzz-smoke on $fuzz_nightly)"
fi
exit "$fail"
