#!/bin/sh
# Create a private, validated PostgreSQL custom-format backup plus SHA-256
# sidecar. The database URL stays in PGDATABASE rather than the process
# argument list. Existing output is never overwritten.
set -eu
umask 077

if [ "$#" -ne 1 ]; then
  echo "usage: E6IRC_DATABASE_URL=... $0 OUTPUT.dump" >&2
  exit 2
fi
: "${E6IRC_DATABASE_URL:?E6IRC_DATABASE_URL is required}"

output=$1
checksum="${output}.sha256"
if [ -e "$output" ] || [ -e "$checksum" ]; then
  echo "backup output already exists: $output or $checksum" >&2
  exit 1
fi
if ! (set -C; : >"$output") 2>/dev/null; then
  echo "backup output was created concurrently: $output" >&2
  exit 1
fi
if ! (set -C; : >"$checksum") 2>/dev/null; then
  rm -f "$output"
  echo "backup checksum output was created concurrently: $checksum" >&2
  exit 1
fi
directory=$(dirname "$output")
name=$(basename "$output")
temporary=
checksum_temporary=
reserved=true
cleanup() {
  [ -z "$temporary" ] || rm -f "$temporary"
  [ -z "$checksum_temporary" ] || rm -f "$checksum_temporary"
  if [ "$reserved" = true ]; then
    rm -f "$output" "$checksum"
  fi
}
trap cleanup EXIT HUP INT TERM
temporary=$(mktemp "$directory/.${name}.tmp.XXXXXX")
checksum_temporary=$(mktemp "$directory/.${name}.sha256.tmp.XXXXXX")

export PGDATABASE="$E6IRC_DATABASE_URL"
pg_dump \
  --format=custom \
  --compress=9 \
  --no-owner \
  --no-privileges \
  --file="$temporary"
pg_restore --list "$temporary" >/dev/null

if command -v sha256sum >/dev/null 2>&1; then
  digest=$(sha256sum "$temporary" | awk '{print $1}')
else
  digest=$(shasum -a 256 "$temporary" | awk '{print $1}')
fi
printf '%s  %s\n' "$digest" "$name" >"$checksum_temporary"
mv "$temporary" "$output"
mv "$checksum_temporary" "$checksum"
reserved=false
trap - EXIT HUP INT TERM
echo "backup written: $output"
