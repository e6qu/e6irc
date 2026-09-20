#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/load/qualify-arguments.sh"

# `! command` is exempt from errexit, so a bare negation asserts nothing.
refuses() {
  if "$@" >/dev/null 2>&1; then
    echo "expected a refusal: $*" >&2
    exit 1
  fi
}

positive_decimal 1
positive_decimal 0.01
refuses positive_decimal 0
refuses positive_decimal 0.00
refuses positive_decimal 0.0
refuses positive_decimal nan

qualification_host_label scale-host-01
qualification_host_label host.example
refuses qualification_host_label ''
refuses qualification_host_label -host
refuses qualification_host_label host-
refuses qualification_host_label 'host name'

[[ "$(target_port 127.0.0.1:6667)" == 6667 ]]
[[ "$(target_port '[::1]:6697')" == 6697 ]]
refuses target_port 127.0.0.1
refuses target_port 127.0.0.1:0
refuses target_port 127.0.0.1:65536
refuses target_port ::1:6667

validate_qualification_arguments 100000 200 20
refuses validate_qualification_arguments 100001 1 1
refuses validate_qualification_arguments 100000 100000 1
refuses validate_qualification_arguments 2 1 10000001
refuses validate_qualification_arguments 100000 1 102
