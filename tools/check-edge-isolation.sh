#!/usr/bin/env bash
# DESIGN §2, "the edge cannot reach the database": the e6irc-edge crate holds
# client connections through a core restart, so nothing it is built from may
# speak to PostgreSQL or carry the core. Its whole dependency graph — normal,
# build and dev dependencies, every feature, every target platform — may name
# none of:
#
#   sqlx and its parts (sqlx-*)          the database driver
#   tokio-postgres, postgres, pq-sys     any other way to PostgreSQL
#   e6ircd                               the core, which holds the database
#   reqwest                              the bridges' HTTP client
#
# A forbidden crate is named with the path cargo reaches it by. The graph is
# read with `cargo tree --locked`, so a lock that does not match the manifests
# fails here too. tools/test-check-edge-isolation.sh holds the contract.
# Portable to bash 3.2.
set -euo pipefail

cd "$(dirname "$0")/.."

forbidden='^(sqlx|sqlx-.*|tokio-postgres|postgres|pq-sys|e6ircd|reqwest)$'

tree=$(cargo tree --locked -p e6irc-edge --all-features --target all \
  -e normal,build,dev --prefix none --format '{p}')

# An empty or foreign graph would pass the name check without judging anything.
if ! printf '%s\n' "$tree" | grep -q '^e6irc-edge v'; then
  echo "edge isolation guard: cargo tree did not list e6irc-edge; nothing was checked" >&2
  exit 1
fi

found=$(printf '%s\n' "$tree" | awk '{print $1}' | grep -E "$forbidden" | sort -u || true)
if [ -n "$found" ]; then
  echo "edge isolation guard FAILED: e6irc-edge's dependency graph reaches what the edge may never touch (DESIGN §2):" >&2
  for name in $found; do
    echo "  $name, reached by:" >&2
    cargo tree --locked -p e6irc-edge --all-features --target all -e normal,build,dev \
      --invert "$name" --prefix indent 2>&1 | sed 's/^/    /' >&2 || true
  done
  exit 1
fi

echo "edge isolation guard: clean (e6irc-edge reaches no database, core or bridge crate)"
