#!/usr/bin/env bash
# Run irctest against a locally built e6ircd. Subshell-safe: never
# changes the caller's working directory.
#   vendor/tests/irctest/run.sh <irctest-checkout> <python-with-deps> [pytest args...]
# With no pytest arguments, runs the exact DB-less CI green list. Supplying
# arguments replaces that list, which keeps focused local reproduction easy.
set -euo pipefail
IRCTEST_DIR=$1
PYTHON=$2
shift 2
REPO_ROOT=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
MARKERS='not implementation-specific and not deprecated and not strict and not services'
# extended_join.py and account_tag.py are deliberately absent here: both
# files consist solely of `services`-marked classes, so under this job's
# `not services` filter they collect zero tests. They run in the
# persistence-backed job (the irctest-services workflow), where the account
# store exists.
GREEN_TESTS=(
    irctest/server_tests/connection_registration.py
    irctest/server_tests/pingpong.py
    irctest/server_tests/utf8.py
    irctest/server_tests/join.py
    irctest/server_tests/part.py
    irctest/server_tests/quit.py
    irctest/server_tests/topic.py
    irctest/server_tests/names.py
    irctest/server_tests/lusers.py
    irctest/server_tests/kick.py
    irctest/server_tests/invite.py
    irctest/server_tests/away.py
    irctest/server_tests/list.py
    irctest/server_tests/away_notify.py
    irctest/server_tests/multi_prefix.py
    irctest/server_tests/setname.py
    irctest/server_tests/message_tags.py
    irctest/server_tests/echo_message.py
    irctest/server_tests/monitor.py
    irctest/server_tests/whowas.py
    irctest/server_tests/time.py
    irctest/server_tests/chmodes/key.py
    irctest/server_tests/chmodes/moderated.py
    irctest/server_tests/chmodes/limit.py
    irctest/server_tests/chmodes/ban.py
    irctest/server_tests/chmodes/invite_exception.py
    irctest/server_tests/chmodes/no_external.py
    irctest/server_tests/chmodes/operator.py
    irctest/server_tests/chmodes/secret.py
    irctest/server_tests/chmodes/modeis.py
    irctest/server_tests/chmodes/no_ctcp.py
    irctest/server_tests/kill.py
    irctest/server_tests/wallops.py
    irctest/server_tests/bot_mode.py
    irctest/server_tests/oper.py
    irctest/server_tests/info.py
    irctest/server_tests/who.py
    irctest/server_tests/whois.py
    irctest/server_tests/labeled_responses.py
    irctest/server_tests/messages.py
    irctest/server_tests/statusmsg.py
    irctest/server_tests/buffering.py
    irctest/server_tests/cap.py
    irctest/server_tests/channel.py
    irctest/server_tests/help.py
    irctest/server_tests/isupport.py
    irctest/server_tests/readq.py
    irctest/server_tests/read_marker.py
    irctest/server_tests/links.py
    irctest/server_tests/multiline.py
    irctest/server_tests/websocket.py
    irctest/server_tests/regressions.py
)
if (( $# == 0 )); then
    set -- "${GREEN_TESTS[@]}"
fi
(
    cd -- "$IRCTEST_DIR"
    PATH="$REPO_ROOT/target/debug:$PATH" \
    PYTHONPATH="$REPO_ROOT/vendor/tests/irctest" \
    "$PYTHON" -m pytest --controller=e6ircd_controller --timeout=15 \
        -m "$MARKERS" "$@"
)
