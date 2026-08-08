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
