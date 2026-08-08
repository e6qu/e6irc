#!/usr/bin/env bash
# Run one budgeted Linux load qualification and retain its evidence.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/qualify-arguments.sh"

usage() {
  echo "usage: $0 ADDR SERVER_PID CLIENTS CHANNELS BURST OUTPUT_DIR MIN_CONNECT_RATE MIN_FANOUT_RATE MAX_P99_MS MAX_RSS_BYTES_PER_CONNECTION" >&2
  exit 2
}

[[ "$(uname -s)" == Linux ]] || { echo "Linux is required" >&2; exit 2; }
[[ $# -eq 10 ]] || usage

addr="$1"
server_pid="$2"
clients="$3"
channels="$4"
burst="$5"
output_dir="$6"
minimum_connect_rate="$7"
minimum_fanout_rate="$8"
maximum_p99_ms="$9"
maximum_rss_per_connection="${10}"

for value in "$server_pid" "$maximum_rss_per_connection"; do
  positive_integer "$value" || { echo "positive integer required: $value" >&2; exit 2; }
done
for value in "$minimum_connect_rate" "$minimum_fanout_rate" "$maximum_p99_ms"; do
  positive_decimal "$value" || { echo "positive decimal required: $value" >&2; exit 2; }
done
validate_qualification_arguments "$clients" "$channels" "$burst" || {
  echo "workload must fit e6irc-load's 100000-client and 10000000-message limits" >&2
  exit 2
}
[[ -r "/proc/$server_pid/limits" ]] || { echo "cannot inspect server PID $server_pid" >&2; exit 2; }
server_executable="$(readlink -f "/proc/$server_pid/exe")"
[[ "$(basename "$server_executable")" == e6ircd ]] || { echo "PID $server_pid is not e6ircd" >&2; exit 2; }

required_fds=$((clients + 1024))
load_nofile="$(ulimit -n)"
server_nofile="$(awk '$1 == "Max" && $2 == "open" && $3 == "files" { print $4 }' "/proc/$server_pid/limits")"
enough_fds() { [[ "$1" == unlimited || "$1" -ge "$required_fds" ]]; }
enough_fds "$load_nofile" || { echo "load process needs at least $required_fds file descriptors (has $load_nofile)" >&2; exit 2; }
enough_fds "$server_nofile" || { echo "server needs at least $required_fds file descriptors (has $server_nofile)" >&2; exit 2; }

read -r port_low port_high < /proc/sys/net/ipv4/ip_local_port_range
port_capacity=$((port_high - port_low + 1))
[[ "$clients" -le "$port_capacity" ]] || { echo "one load host has $port_capacity ephemeral ports, below $clients clients" >&2; exit 2; }
somaxconn="$(cat /proc/sys/net/core/somaxconn)"
[[ "$somaxconn" -ge "$clients" ]] || { echo "net.core.somaxconn must be at least $clients (has $somaxconn)" >&2; exit 2; }

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
load_bin="$root/target/release/e6irc-load"
if [[ ! -x "$load_bin" ]]; then
  (cd "$root" && cargo build --release -p e6irc-load >&2)
fi

[[ ! -e "$output_dir" ]] || { echo "OUTPUT_DIR must not already exist: $output_dir" >&2; exit 2; }
mkdir -p "$output_dir"
result="$output_dir/result.json"
host="$output_dir/host.txt"
{
  date -u +%Y-%m-%dT%H:%M:%SZ
  git -C "$root" rev-parse HEAD
  uname -a
  nproc
  grep -E '^(Model name|MemTotal):' /proc/cpuinfo /proc/meminfo
  printf 'server_executable=%s\n' "$server_executable"
  sha256sum "$server_executable"
  printf 'load_nofile=%s\nserver_nofile=%s\nrequired_fds=%s\n' "$load_nofile" "$server_nofile" "$required_fds"
  printf 'ephemeral_port_range=%s %s\nephemeral_port_capacity=%s\nsomaxconn=%s\n' "$port_low" "$port_high" "$port_capacity" "$somaxconn"
} > "$host"

"$load_bin" \
  --addr "$addr" \
  --server-pid "$server_pid" \
  --clients "$clients" \
  --channels "$channels" \
  --burst "$burst" \
  --minimum-connect-rate "$minimum_connect_rate" \
  --minimum-fanout-rate "$minimum_fanout_rate" \
  --maximum-p99-ms "$maximum_p99_ms" \
  --maximum-server-rss-per-connection-bytes "$maximum_rss_per_connection" \
  --report-json "$result"

echo "qualification evidence: $result and $host"
