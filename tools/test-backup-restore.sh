#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/e6irc-backup-test.XXXXXX")
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
mkdir "$temporary/bin"

# Every stub that would open a connection records what it was handed: its
# arguments, and the libpq environment the connection would be made from.
cat >"$temporary/bin/record-connection" <<'EOF'
#!/bin/sh
printf '%s\n' "$*" >>"${E6IRC_TEST_ARGUMENT_LOG:?}"
{
  printf 'PGHOST=%s\nPGPORT=%s\nPGUSER=%s\n' "${PGHOST-}" "${PGPORT-}" "${PGUSER-}"
  printf 'PGPASSWORD=%s\nPGDATABASE=%s\n' "${PGPASSWORD-}" "${PGDATABASE-}"
  printf 'PGSSLMODE=%s\nPGSSLROOTCERT=%s\n' "${PGSSLMODE-}" "${PGSSLROOTCERT-}"
  printf 'E6IRC_DATABASE_URL=%s\n' "${E6IRC_DATABASE_URL-}"
} >"${E6IRC_TEST_ENVIRONMENT_LOG:?}"
EOF
cat >"$temporary/bin/pg_dump" <<'EOF'
#!/bin/sh
set -eu
record-connection pg_dump "$@"
for argument in "$@"; do
  case "$argument" in
    --file=*) output=${argument#--file=} ;;
  esac
done
: "${output:?missing --file}"
printf 'e6irc custom backup fixture\n' >"$output"
EOF
cat >"$temporary/bin/pg_restore" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = "--list" ]; then
  printf 'fixture archive listing\n'
  exit 0
fi
record-connection pg_restore "$@"
printf '%s\n' "$*" >"${E6IRC_TEST_RESTORE_LOG:?}"
EOF
cat >"$temporary/bin/psql" <<'EOF'
#!/bin/sh
set -eu
record-connection psql "$@"
printf '%s\n' "${E6IRC_TEST_DATABASE_NAME:?}"
EOF
chmod +x "$temporary/bin/record-connection" "$temporary/bin/pg_dump" \
  "$temporary/bin/pg_restore" "$temporary/bin/psql"

# libpq expands a URL only from an explicit database-name argument, never from
# PGDATABASE, so each connecting client must receive the URL's fields in the
# per-field variables: percent-decoded, and with neither the URL nor the
# password anywhere in its arguments.
expected_environment='PGHOST=db.example.invalid
PGPORT=6543
PGUSER=backup user
PGPASSWORD=p@ss/w:rd#1
PGDATABASE=e6irc_restore
PGSSLMODE=verify-full
PGSSLROOTCERT=/etc/e6irc/database ca.pem
E6IRC_DATABASE_URL='
assert_connection() {
  if [ "$(cat "$E6IRC_TEST_ENVIRONMENT_LOG")" != "$expected_environment" ]; then
    echo "$1 did not receive the database URL as libpq variables:" >&2
    cat "$E6IRC_TEST_ENVIRONMENT_LOG" >&2
    exit 1
  fi
  rm "$E6IRC_TEST_ENVIRONMENT_LOG"
}

export PATH="$temporary/bin:$PATH"
export E6IRC_TEST_ARGUMENT_LOG="$temporary/arguments.log"
export E6IRC_TEST_ENVIRONMENT_LOG="$temporary/environment.log"
export E6IRC_DATABASE_URL='postgresql://backup%20user:p%40ss%2Fw%3Ard%231@db.example.invalid:6543/e6irc_restore?sslmode=verify-full&ssl-root-cert=/etc/e6irc/database%20ca.pem&statement-cache-capacity=10'
backup="$temporary/e6irc.dump"
"$root/tools/backup-postgres.sh" "$backup"
test -s "$backup"
test -s "$backup.sha256"
assert_connection pg_dump
if "$root/tools/backup-postgres.sh" "$backup" >/dev/null 2>&1; then
  echo "backup overwrote existing output" >&2
  exit 1
fi

export E6IRC_TEST_DATABASE_NAME=e6irc_restore
export E6IRC_TEST_RESTORE_LOG="$temporary/restore.log"
if E6IRC_RESTORE_CONFIRM=wrong \
  "$root/tools/restore-postgres.sh" "$backup" e6irc_restore >/dev/null 2>&1; then
  echo "restore accepted a wrong confirmation" >&2
  exit 1
fi
E6IRC_RESTORE_CONFIRM=e6irc_restore \
  "$root/tools/restore-postgres.sh" "$backup" e6irc_restore
grep -F -- '--single-transaction' "$temporary/restore.log" >/dev/null
grep -F -- '--clean' "$temporary/restore.log" >/dev/null
grep -F -- '--dbname=' "$temporary/restore.log" >/dev/null
assert_connection pg_restore
grep '^psql ' "$E6IRC_TEST_ARGUMENT_LOG" >/dev/null
if grep -E 'postgresql:|p@ss|p%40ss|db\.example' "$E6IRC_TEST_ARGUMENT_LOG" >&2; then
  echo "a PostgreSQL client received part of the database URL as an argument" >&2
  exit 1
fi

printf 'tamper\n' >>"$backup"
if E6IRC_RESTORE_CONFIRM=e6irc_restore \
  "$root/tools/restore-postgres.sh" "$backup" e6irc_restore >/dev/null 2>&1; then
  echo "restore accepted a checksum mismatch" >&2
  exit 1
fi

# A URL the tools cannot express to libpq is refused before any client runs,
# and the refusal repeats nothing the URL contained.
: >"$E6IRC_TEST_ARGUMENT_LOG"
for unusable in \
  'postgresql://u:hunter2@db.example.invalid/e6irc?target_session_attrs=hunter2' \
  'postgresql://u:hunter2#x@db.example.invalid/e6irc' \
  'postgresql://u:hunter2@db.example.invalid:hunter2/e6irc' \
  'postgresql://u:hunter2@one.invalid,two.invalid/e6irc' \
  'postgresql://u:hunter2@db.example.invalid/e6irc?options=-c+hunter2' \
  'postgresql://u:hunter%FF2@db.example.invalid/e6irc' \
  'mysql://u:hunter2@db.example.invalid/e6irc'; do
  if E6IRC_DATABASE_URL=$unusable \
    "$root/tools/backup-postgres.sh" "$temporary/unusable.dump" >"$temporary/unusable.log" 2>&1; then
    echo "backup accepted a database URL it cannot express to libpq" >&2
    exit 1
  fi
  grep -F 'E6IRC_DATABASE_URL cannot be used' "$temporary/unusable.log" >/dev/null
  if grep -E 'hunter|example|invalid/' "$temporary/unusable.log" >&2; then
    echo "a refused database URL was repeated in the refusal" >&2
    exit 1
  fi
  test ! -e "$temporary/unusable.dump"
  test ! -s "$E6IRC_TEST_ARGUMENT_LOG"
done

echo "backup/restore contract ok"
