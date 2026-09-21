#!/usr/bin/env bash
# The native release jobs build with the same Rust release as the container
# image. The Dockerfile pins its build image by digest and records the Rust
# version that digest carries; release.yml must name that exact version, so a
# refresh of one without the other fails here instead of shipping two
# compilers' output under one tag.
set -euo pipefail

cd "$(dirname "$0")/.."

image_version="$(sed -n 's/^#   rust:1-bookworm .*(Rust \([0-9][0-9.]*\)).*/\1/p' Dockerfile)"
if [ -z "$image_version" ]; then
  echo "Dockerfile does not record the Rust version of its pinned rust:1-bookworm image" >&2
  exit 1
fi
release_versions="$(sed -n '/native-build:/,/^  [a-z-]*:$/s/^ *toolchain: *\(.*\)$/\1/p' .github/workflows/release.yml | sort -u)"
if [ "$release_versions" != "$image_version" ]; then
  echo "release.yml native builds use toolchain '${release_versions:-none}', but the Dockerfile's image carries Rust $image_version" >&2
  exit 1
fi
if sed -n '/native-build:/,/^  [a-z-]*:$/p' .github/workflows/release.yml | grep -q 'rust-cache'; then
  echo "release.yml native builds must not restore a build cache" >&2
  exit 1
fi
