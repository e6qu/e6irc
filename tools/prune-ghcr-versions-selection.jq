# Given a GitHub Container Registry package-versions array and $keep, emit the
# IDs of versions outside the newest immutable short-SHA releases. Each release
# consists of the generic tag, its direct arm64/amd64 siblings, and untagged OCI
# referrers (provenance/SBOM attestations). The package API does not expose a
# referrer's subject, so an untagged version is retained when it is at least as
# new as the oldest kept release and pruned only after it crosses that bound.
def is_release_tag: test("^[0-9a-f]{12}$");
def release_tags: [.metadata.container.tags[]? | select(is_release_tag)];

(map(select((release_tags | length) > 0)) | sort_by(.created_at) | reverse | .[:$keep]) as $releases
| ($releases | map(release_tags[]) | map(., . + "-arm64", . + "-amd64") | unique) as $kept_tags
| ($releases | map(.created_at) | min) as $oldest_kept
| map(
    select(
      if (.metadata.container.tags // [] | length) > 0
      then all(.metadata.container.tags[]?; . as $tag | $kept_tags | index($tag) == null)
      else $oldest_kept != null and .created_at < $oldest_kept
      end
    )
  )
| .[].id
