#!/usr/bin/env bash
# Run one budgeted Linux load qualification and retain its evidence.
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/qualify-arguments.sh"

usage() {
  echo "usage: $0 ADDR SERVER_PID CORE_WORKERS CLIENTS CHANNELS BURST OUTPUT_DIR MIN_CONNECT_RATE MIN_FANOUT_RATE MAX_P99_MS MAX_RSS_BYTES_PER_CONNECTION" >&2
  exit 2
}

[[ "$(uname -s)" == Linux ]] || { echo "Linux is required" >&2; exit 2; }
[[ $# -eq 11 ]] || usage

addr="$1"
server_pid="$2"
core_workers="$3"
clients="$4"
channels="$5"
burst="$6"
output_dir="$7"
minimum_connect_rate="$8"
minimum_fanout_rate="$9"
maximum_p99_ms="${10}"
maximum_rss_per_connection="${11}"
qualification_host="${E6IRC_QUALIFICATION_HOST:?E6IRC_QUALIFICATION_HOST is required}"

for value in "$server_pid" "$core_workers" "$maximum_rss_per_connection"; do
  positive_integer "$value" || { echo "positive integer required: $value" >&2; exit 2; }
done
for value in "$minimum_connect_rate" "$minimum_fanout_rate" "$maximum_p99_ms"; do
  positive_decimal "$value" || { echo "positive decimal required: $value" >&2; exit 2; }
done
validate_qualification_arguments "$clients" "$channels" "$burst" || {
  echo "workload must fit e6irc-load's 100000-client and 10000000-message limits" >&2
  exit 2
}
target_port="$(target_port "$addr")" || { echo "ADDR must be host:port or [ipv6]:port" >&2; exit 2; }
[[ -r "/proc/$server_pid/limits" ]] || { echo "cannot inspect server PID $server_pid" >&2; exit 2; }
server_executable="$(readlink -f "/proc/$server_pid/exe")"
[[ "$(basename "$server_executable")" == e6ircd ]] || { echo "PID $server_pid is not e6ircd" >&2; exit 2; }
command -v ss >/dev/null || { echo "ss is required to verify the target listener" >&2; exit 2; }
listener="$(ss -H -ltnp "sport = :$target_port" 2>/dev/null || true)"
grep -Fq "pid=$server_pid," <<<"$listener" || {
  echo "PID $server_pid is not listening on target port $target_port" >&2
  exit 2
}

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
qualification_bin="$root/target/release/e6irc-qualification"
[[ -z "$(git -C "$root" status --porcelain)" ]] || {
  echo "qualification requires a clean source tree" >&2
  exit 2
}
if [[ ! -x "$load_bin" ]]; then
  (cd "$root" && cargo build --release -p e6irc-load >&2)
fi
if [[ ! -x "$qualification_bin" ]]; then
  (cd "$root" && cargo build --release -p e6irc-qualification >&2)
fi

[[ ! -e "$output_dir" ]] || { echo "OUTPUT_DIR must not already exist: $output_dir" >&2; exit 2; }
mkdir -p "$output_dir"
result="$output_dir/result.json"
evidence="$output_dir/qualification.json"
host="$output_dir/host.txt"
{
  date -u +%Y-%m-%dT%H:%M:%SZ
  git -C "$root" rev-parse HEAD
  uname -a
  nproc
  grep -E '^(Model name|MemTotal):' /proc/cpuinfo /proc/meminfo
  printf 'load_executable=%s\n' "$load_bin"
  sha256sum "$load_bin"
  printf 'server_executable=%s\n' "$server_executable"
  sha256sum "$server_executable"
  printf 'load_nofile=%s\nserver_nofile=%s\nrequired_fds=%s\n' "$load_nofile" "$server_nofile" "$required_fds"
  printf 'ephemeral_port_range=%s %s\nephemeral_port_capacity=%s\nsomaxconn=%s\n' "$port_low" "$port_high" "$port_capacity" "$somaxconn"
  printf 'addr=%s\ncore_workers=%s\nclients=%s\nchannels=%s\nburst=%s\n' "$addr" "$core_workers" "$clients" "$channels" "$burst"
  printf 'minimum_connect_rate=%s\nminimum_fanout_rate=%s\nmaximum_p99_ms=%s\nmaximum_rss_per_connection=%s\n' \
    "$minimum_connect_rate" "$minimum_fanout_rate" "$maximum_p99_ms" "$maximum_rss_per_connection"
} > "$host"
host_sha256="$(sha256sum "$host" | awk '{print $1}')"

set +e
"$qualification_bin" scale \
  --target "$addr" \
  --source "$(git -C "$root" rev-parse HEAD)" \
  --host "$qualification_host" \
  --executable "$server_executable" \
  --output "$evidence" \
  --workload "core_workers=$core_workers" \
  --workload "clients=$clients" \
  --workload "channels=$channels" \
  --workload "burst=$burst" \
  --budget "minimum_connect_rate=$minimum_connect_rate" \
  --budget "minimum_fanout_rate=$minimum_fanout_rate" \
  --budget "maximum_p99_ms=$maximum_p99_ms" \
  --budget "maximum_rss_per_connection=$maximum_rss_per_connection" \
  --probe "$root/tools/qualification/scale-probe.sh" \
  -- "$load_bin" "$result" \
    --addr "$addr" \
    --server-pid "$server_pid" \
    --clients "$clients" \
    --channels "$channels" \
    --burst "$burst" \
    --minimum-connect-rate "$minimum_connect_rate" \
    --minimum-fanout-rate "$minimum_fanout_rate" \
    --maximum-p99-ms "$maximum_p99_ms" \
    --maximum-server-rss-per-connection-bytes "$maximum_rss_per_connection" \
    --host-provenance-sha256 "$host_sha256" \
    --report-json "$result"
status=$?
set -e

if [[ "$status" -ne 0 ]]; then
  echo "qualification rejected or failed; evidence: $evidence, $result, and $host" >&2
  exit "$status"
fi
echo "qualification evidence: $evidence, $result, and $host"
