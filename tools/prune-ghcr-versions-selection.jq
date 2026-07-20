# Given a GitHub Container Registry package-versions array and $keep, emit the
# IDs of tagged versions outside the newest immutable short-SHA releases. Each
# release consists of the generic tag and its direct arm64/amd64 siblings.
def is_release_tag: test("^[0-9a-f]{12}$");
def release_tags: [.metadata.container.tags[]? | select(is_release_tag)];

(map(select((release_tags | length) > 0)) | sort_by(.created_at) | reverse | .[:$keep]) as $releases
| ($releases | map(release_tags[]) | map(., . + "-arm64", . + "-amd64") | unique) as $kept_tags
| map(
    select((.metadata.container.tags // [] | length) > 0)
    | select(all(.metadata.container.tags[]?; . as $tag | $kept_tags | index($tag) == null))
  )
| .[].id
