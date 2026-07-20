#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 2 ]]; then
  echo "usage: tools/verify-container-shape.sh <image:tag> <arm64|amd64|manifest>" >&2
  exit 2
fi

image="$1"
shape="$2"
case "$shape" in
  arm64 | amd64) reference="${image}-${shape}" ;;
  manifest) reference="$image" ;;
  *)
    echo "shape must be arm64, amd64, or manifest (got ${shape})" >&2
    exit 2
    ;;
esac

metadata="$(docker buildx imagetools inspect --format '{{json .}}' "$reference")"
media_type="$(jq -r '.manifest.mediaType' <<<"$metadata")"

if [[ "$shape" != "manifest" ]]; then
  if [[ "$media_type" != "application/vnd.oci.image.manifest.v1+json" ]]; then
    echo "${reference} is ${media_type}, expected a direct OCI image manifest" >&2
    exit 1
  fi
  if [[ "$(jq -r '.manifest | has("manifests")' <<<"$metadata")" != "false" ]]; then
    echo "${reference} unexpectedly contains a nested manifest list" >&2
    exit 1
  fi
  actual_platform="$(jq -r '.image.os + "/" + .image.architecture' <<<"$metadata")"
  if [[ "$actual_platform" != "linux/${shape}" ]]; then
    echo "${reference} has platform ${actual_platform}, expected linux/${shape}" >&2
    exit 1
  fi
  echo "verified direct ${actual_platform} image manifest: ${reference}"
  exit 0
fi

if [[ "$media_type" != "application/vnd.oci.image.index.v1+json" ]]; then
  echo "${reference} is ${media_type}, expected an OCI image index" >&2
  exit 1
fi
manifest_count="$(jq '.manifest.manifests | length' <<<"$metadata")"
if [[ "$manifest_count" -ne 2 ]]; then
  echo "${reference} contains ${manifest_count} manifests, expected exactly 2" >&2
  exit 1
fi
if [[ "$(jq '[.manifest.manifests[] | select(.mediaType != "application/vnd.oci.image.manifest.v1+json")] | length' <<<"$metadata")" -ne 0 ]]; then
  echo "${reference} contains a non-image child manifest" >&2
  exit 1
fi
platforms="$(jq -r '.manifest.manifests[] | .platform.os + "/" + .platform.architecture' <<<"$metadata" | sort)"
expected_platforms="$(printf 'linux/amd64\nlinux/arm64')"
if [[ "$platforms" != "$expected_platforms" ]]; then
  echo "${reference} has unexpected platforms:" >&2
  printf '%s\n' "$platforms" >&2
  exit 1
fi
echo "verified Linux amd64/arm64 image index: ${reference}"
