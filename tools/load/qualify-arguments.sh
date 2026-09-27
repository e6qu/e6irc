#!/usr/bin/env bash

readonly E6IRC_LOAD_MAX_CLIENTS=100000
readonly E6IRC_LOAD_MAX_TRACKED_MESSAGES=10000000

positive_integer() {
  [[ "$1" =~ ^[1-9][0-9]*$ ]]
}

decimal_at_most() {
  local value="$1" maximum="$2"
  [[ ${#value} -lt ${#maximum} || ( ${#value} -eq ${#maximum} && "$value" < "$maximum" ) || "$value" == "$maximum" ]]
}

positive_decimal() {
  [[ "$1" =~ ^[0-9]+([.][0-9]+)?$ && "${1//[.0]/}" ]]
}

qualification_host_label() {
  [[ ${#1} -gt 0 && ${#1} -le 253 && "$1" =~ ^[[:alnum:]]([[:alnum:]._-]*[[:alnum:]])?$ ]]
}

target_port() {
  local target="$1" port
  if [[ "$target" =~ ^\[[^]]+\]:([0-9]+)$ ]]; then
    port="${BASH_REMATCH[1]}"
  elif [[ "$target" =~ ^[^:]+:([0-9]+)$ ]]; then
    port="${BASH_REMATCH[1]}"
  else
    return 1
  fi
  positive_integer "$port" && decimal_at_most "$port" 65535 || return 1
  printf '%s\n' "$port"
}

# e6ircd's default `limits.command_burst`, as `e6irc-load --server-command-burst`
# assumes it.
readonly E6IRC_LOAD_DEFAULT_COMMAND_BURST=40

# Whether a sender's burst and its fence line fit the server's default command
# burst, so the flood limiter does not meter it; past it the senders must oper
# up (IRC operators are exempt) or the run measures the limiter.
burst_within_command_burst() {
  positive_integer "$1" && ((10#$1 + 1 <= E6IRC_LOAD_DEFAULT_COMMAND_BURST))
}

# The server's HTTP listener as the load harness reads its monitoring
# observation: plain http://HOST:PORT on the qualification host.
monitoring_url() {
  [[ "$1" =~ ^http://([^/?#@]+)/?$ ]] && target_port "${BASH_REMATCH[1]}" >/dev/null
}

validate_qualification_arguments() {
  local clients="$1" channels="$2" burst="$3"
  positive_integer "$clients" && positive_integer "$channels" && positive_integer "$burst" || return 1
  decimal_at_most "$clients" "$E6IRC_LOAD_MAX_CLIENTS" || return 1
  decimal_at_most "$channels" "$E6IRC_LOAD_MAX_CLIENTS" || return 1
  decimal_at_most "$burst" "$E6IRC_LOAD_MAX_TRACKED_MESSAGES" || return 1
  ((10#$clients > 10#$channels)) || return 1
  local sender_slots=$((10#$channels * 10#$burst))
  local expected_deliveries=$(((10#$clients - 10#$channels) * 10#$burst))
  [[ "$sender_slots" -le "$E6IRC_LOAD_MAX_TRACKED_MESSAGES" && "$expected_deliveries" -le "$E6IRC_LOAD_MAX_TRACKED_MESSAGES" ]]
}
