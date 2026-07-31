#!/bin/sh
set -eu

root=$(CDPATH='' cd -- "$(dirname "$0")/.." && pwd)
temporary=$(mktemp -d "${TMPDIR:-/tmp}/e6irc-backup-test.XXXXXX")
cleanup() {
  rm -rf "$temporary"
}
trap cleanup EXIT HUP INT TERM
mkdir "$temporary/bin"

cat >"$temporary/bin/pg_dump" <<'EOF'
#!/bin/sh
set -eu
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
printf '%s\n' "$*" >"${E6IRC_TEST_RESTORE_LOG:?}"
EOF
cat >"$temporary/bin/psql" <<'EOF'
#!/bin/sh
printf '%s\n' "${E6IRC_TEST_DATABASE_NAME:?}"
EOF
chmod +x "$temporary/bin/pg_dump" "$temporary/bin/pg_restore" "$temporary/bin/psql"

export PATH="$temporary/bin:$PATH"
export E6IRC_DATABASE_URL='postgresql://secret@example.invalid/e6irc_restore'
backup="$temporary/e6irc.dump"
"$root/tools/backup-postgres.sh" "$backup"
test -s "$backup"
test -s "$backup.sha256"
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

printf 'tamper\n' >>"$backup"
if E6IRC_RESTORE_CONFIRM=e6irc_restore \
  "$root/tools/restore-postgres.sh" "$backup" e6irc_restore >/dev/null 2>&1; then
  echo "restore accepted a checksum mismatch" >&2
  exit 1
fi

echo "backup/restore contract ok"
