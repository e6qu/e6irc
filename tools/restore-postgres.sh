#!/bin/sh
# Restore one validated e6irc PostgreSQL backup into an explicitly confirmed
# database. Stop e6ircd first: a live process could write old-key or
# post-backup state while the destructive replacement is running.
set -eu

if [ "$#" -ne 2 ]; then
  echo "usage: E6IRC_DATABASE_URL=... E6IRC_RESTORE_CONFIRM=DATABASE $0 BACKUP.dump DATABASE" >&2
  exit 2
fi
: "${E6IRC_DATABASE_URL:?E6IRC_DATABASE_URL is required}"

backup=$1
expected_database=$2
checksum="${backup}.sha256"
if [ "${E6IRC_RESTORE_CONFIRM:-}" != "$expected_database" ]; then
  echo "refusing restore: E6IRC_RESTORE_CONFIRM must exactly equal $expected_database" >&2
  exit 1
fi
if [ ! -f "$backup" ] || [ ! -f "$checksum" ]; then
  echo "backup and SHA-256 sidecar are both required" >&2
  exit 1
fi

read -r expected_digest expected_name <"$checksum"
if [ "$expected_name" != "$(basename "$backup")" ]; then
  echo "backup checksum names a different file" >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual_digest=$(sha256sum "$backup" | awk '{print $1}')
else
  actual_digest=$(shasum -a 256 "$backup" | awk '{print $1}')
fi
if [ "$actual_digest" != "$expected_digest" ]; then
  echo "backup checksum mismatch" >&2
  exit 1
fi

export PGDATABASE="$E6IRC_DATABASE_URL"
actual_database=$(psql --no-psqlrc --tuples-only --no-align --command='SELECT current_database()')
if [ "$actual_database" != "$expected_database" ]; then
  echo "refusing restore: connected database is $actual_database, expected $expected_database" >&2
  exit 1
fi
pg_restore --list "$backup" >/dev/null
pg_restore \
  --exit-on-error \
  --single-transaction \
  --clean \
  --if-exists \
  --no-owner \
  --no-privileges \
  --dbname= \
  "$backup"
echo "restore completed: $expected_database"
