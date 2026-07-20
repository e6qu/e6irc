#!/usr/bin/env bash
set -euo pipefail

owner="${1:?usage: prune-ghcr-versions.sh <owner> <package> [keep]}"
package="${2:?usage: prune-ghcr-versions.sh <owner> <package> [keep]}"
keep="${3:-20}"

if [[ ! "$keep" =~ ^[1-9][0-9]*$ ]]; then
  echo "keep must be a positive integer (got ${keep})" >&2
  exit 2
fi

owner_type="$(gh api "/users/${owner}" --jq .type)"
case "$owner_type" in
  Organization) base="/orgs/${owner}/packages/container/${package}/versions" ;;
  User) base="/users/${owner}/packages/container/${package}/versions" ;;
  *)
    echo "unknown owner type: ${owner_type}" >&2
    exit 1
    ;;
esac

versions_file="$(mktemp)"
trap 'rm -f "$versions_file"' EXIT
gh api --paginate "${base}?per_page=100" | jq -s 'add' > "$versions_file"

ids="$(jq -r --argjson keep "$keep" -f "$(dirname "${BASH_SOURCE[0]}")/prune-ghcr-versions-selection.jq" "$versions_file")"
count=0
for id in $ids; do
  gh api -X DELETE "${base}/${id}" >/dev/null
  count=$((count + 1))
done
echo "pruned ${count} image version(s); kept the newest ${keep} release(s)"
