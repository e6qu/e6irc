#!/usr/bin/env bash
set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/load/qualify-arguments.sh"

positive_decimal 1
positive_decimal 0.01
! positive_decimal 0
! positive_decimal 0.00
! positive_decimal 0.0
! positive_decimal nan

validate_qualification_arguments 100000 200 20
! validate_qualification_arguments 100001 1 1
! validate_qualification_arguments 100000 100000 1
! validate_qualification_arguments 2 1 10000001
! validate_qualification_arguments 100000 1 102
