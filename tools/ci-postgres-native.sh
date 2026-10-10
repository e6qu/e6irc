#!/usr/bin/env bash
# Install PostgreSQL 18 natively on a macOS or Windows CI runner and start a
# cluster on 127.0.0.1:5432 with a `postgres` superuser (password `test`) and
# an `e6irc_test` database (D15: the zero-drop suite's PostgreSQL scenarios run
# on every operating system, and those runners have no service containers).
# Writes E6IRC_TEST_DATABASE_URL to "$GITHUB_ENV". Linux jobs use the
# postgres:18 service container instead.
set -euo pipefail

case "${RUNNER_OS:-}" in
  macOS)
    brew install postgresql@18
    bin="$(brew --prefix postgresql@18)/bin"
    ;;
  Windows)
    choco install postgresql18 --no-progress -y --params "/Password:test /Port:5433"
    bin="/c/Program Files/PostgreSQL/18/bin"
    ;;
  *)
    echo "ci-postgres-native: RUNNER_OS is '${RUNNER_OS:-}', not macOS or Windows" >&2
    exit 1
    ;;
esac

data="${RUNNER_TEMP:?}/e6irc-pg18"
printf 'test\n' > "${RUNNER_TEMP}/pgpass"
"$bin/initdb" --pgdata "$data" --username postgres --auth scram-sha-256 \
  --pwfile "${RUNNER_TEMP}/pgpass" --encoding UTF8 --no-locale
"$bin/pg_ctl" --pgdata "$data" --log "${RUNNER_TEMP}/e6irc-pg18.log" \
  --options "-p 5432 -c listen_addresses=127.0.0.1 -c max_connections=300" --wait start
PGPASSWORD=test "$bin/createdb" --host 127.0.0.1 --port 5432 --username postgres e6irc_test
echo "E6IRC_TEST_DATABASE_URL=postgres://postgres:test@127.0.0.1:5432/e6irc_test" >> "$GITHUB_ENV"
"$bin/postgres" --version
