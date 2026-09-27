#!/usr/bin/env bash
# Run a built image's own binary and require it to name the workspace version
# and the commit it was built from: `e6ircd --version` through the image's
# entrypoint must print exactly `e6ircd <version> (revision <commit>)`. An
# image that reports another revision, or `unknown`, is not the build it is
# about to be published or tested as.
# Portable to bash 3.2.
#
#   tools/check-image-version.sh IMAGE REVISION
set -euo pipefail

[ "$#" -eq 2 ] || { echo "usage: $0 IMAGE REVISION" >&2; exit 2; }
image=$1
revision=$2
cd "$(dirname "$0")/.."

version="$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["workspace"]["package"]["version"])')"
expected="e6ircd $version (revision $revision)"
reported="$(docker run --rm "$image" --version)"
if [ "$reported" != "$expected" ]; then
  echo "$image reports '$reported', not '$expected'" >&2
  exit 1
fi
echo "$image: $reported"
