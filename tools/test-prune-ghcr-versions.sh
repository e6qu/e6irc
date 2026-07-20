#!/usr/bin/env bash
set -euo pipefail

filter="$(dirname "${BASH_SOURCE[0]}")/prune-ghcr-versions-selection.jq"
fixture='[
  {"id":1,"created_at":"2026-01-03T00:00:00Z","metadata":{"container":{"tags":["aaaaaaaaaaaa"]}}},
  {"id":2,"created_at":"2026-01-03T00:00:00Z","metadata":{"container":{"tags":["aaaaaaaaaaaa-arm64"]}}},
  {"id":3,"created_at":"2026-01-03T00:00:00Z","metadata":{"container":{"tags":["aaaaaaaaaaaa-amd64"]}}},
  {"id":4,"created_at":"2026-01-02T00:00:00Z","metadata":{"container":{"tags":["bbbbbbbbbbbb"]}}},
  {"id":5,"created_at":"2026-01-02T00:00:00Z","metadata":{"container":{"tags":["bbbbbbbbbbbb-arm64"]}}},
  {"id":6,"created_at":"2026-01-02T00:00:00Z","metadata":{"container":{"tags":["bbbbbbbbbbbb-amd64"]}}},
  {"id":7,"created_at":"2026-01-01T00:00:00Z","metadata":{"container":{"tags":["latest"]}}},
  {"id":8,"created_at":"2026-01-01T00:00:00Z","metadata":{"container":{"tags":[]}}}
]'

actual="$(jq -r --argjson keep 1 -f "$filter" <<<"$fixture" | sort -n)"
expected="$(printf '4\n5\n6\n7')"
if [[ "$actual" != "$expected" ]]; then
  echo "unexpected package versions selected for deletion:" >&2
  printf '%s\n' "$actual" >&2
  exit 1
fi
echo "GitHub Container Registry retention selection passed"
