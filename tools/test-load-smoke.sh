#!/usr/bin/env bash
set -euo pipefail

server_bin="${E6IRC_TEST_SERVER_BINARY:-target/debug/e6ircd}"
load_bin="${E6IRC_TEST_LOAD_BINARY:-target/debug/e6irc-load}"
test_dir="$(mktemp -d)"
server_pid=""

cleanup() {
  if [[ -n "$server_pid" ]] && kill -0 "$server_pid" 2>/dev/null; then
    kill -TERM "$server_pid"
    wait "$server_pid" || true
  fi
  rm -rf "$test_dir"
}
trap cleanup EXIT

printf '%s\n' \
  'server_name = "irc.load.test"' \
  'network_name = "LoadTest"' \
  '[[listeners]]' \
  'addr = "127.0.0.1:16671"' \
  > "$test_dir/e6ircd.toml"

"$server_bin" --config "$test_dir/e6ircd.toml" \
  >"$test_dir/server.stdout" 2>"$test_dir/server.stderr" &
server_pid="$!"

ready=false
for _ in $(seq 1 100); do
  if ! kill -0 "$server_pid" 2>/dev/null; then
    echo "e6ircd exited during load-smoke startup" >&2
    cat "$test_dir/server.stdout" "$test_dir/server.stderr" >&2
    exit 1
  fi
  if (exec 3<>/dev/tcp/127.0.0.1/16671) 2>/dev/null; then
    exec 3>&-
    ready=true
    break
  fi
  sleep 0.1
done
if [[ "$ready" != true ]]; then
  echo "e6ircd did not become ready for load smoke" >&2
  cat "$test_dir/server.stdout" "$test_dir/server.stderr" >&2
  exit 1
fi

load_args=(
  --addr 127.0.0.1:16671
  --clients 64
  --channels 8
  --burst 4
  --minimum-connect-rate 10
  --minimum-fanout-rate 100
  --maximum-p99-ms 5000
  --report-json "$test_dir/load-report.json"
)
if [[ "$(uname -s)" == "Linux" ]]; then
  load_args+=(
    --server-pid "$server_pid"
    --maximum-server-rss-per-connection-bytes 1048576
  )
fi

"$load_bin" "${load_args[@]}"
test -s "$test_dir/load-report.json"
grep -F '"status": "completed"' "$test_dir/load-report.json" >/dev/null
grep -F '"format_version": 2' "$test_dir/load-report.json" >/dev/null
grep -F '"outcome": "passed"' "$test_dir/load-report.json" >/dev/null

rejected_report="$test_dir/rejected-load-report.json"
if "$load_bin" --addr 127.0.0.1:16672 --clients 2 --channels 1 --report-json "$rejected_report"; then
  echo "load harness unexpectedly passed against a closed listener" >&2
  exit 1
fi
test -s "$rejected_report"
grep -F '"status": "completed"' "$rejected_report" >/dev/null
grep -F '"outcome": "rejected"' "$rejected_report" >/dev/null

failed_report="$test_dir/failed-load-report.json"
if "$load_bin" --server-pid 4294967295 --maximum-server-rss-per-connection-bytes 1 --report-json "$failed_report"; then
  echo "load harness unexpectedly sampled a nonexistent server" >&2
  exit 1
fi
test -s "$failed_report"
grep -F '"status": "failed"' "$failed_report" >/dev/null
grep -F '"error":' "$failed_report" >/dev/null

kill -TERM "$server_pid"
if ! wait "$server_pid"; then
  echo "e6ircd did not shut down cleanly after load smoke" >&2
  cat "$test_dir/server.stdout" "$test_dir/server.stderr" >&2
  exit 1
fi
server_pid=""
