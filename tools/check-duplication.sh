#!/usr/bin/env bash
# check-duplication.sh — copy-paste guard for shipped Rust source.
#
# Duplicated logic is a bug factory: a fix applied to one copy silently rots
# the others. This guard runs jscpd (a token-based clone detector) over the
# crate sources and fails if the duplicated-line percentage exceeds the
# ratchet threshold below.
#
# THRESHOLD is ratchet-only: lower it as duplication drops, never raise it to
# make a red run pass. It exists to stop the copy-paste classes prior sweeps
# removed (the bridge drivers' reconnect loop, the client's SASL handshakes)
# from silently growing back — not to bless the current number as acceptable.
#
# The one exception, and why the number went UP once: jscpd skips files over
# 1000 lines by default, so this guard had never opened handler.rs, http.rs,
# db.rs or state.rs — 60% of the source. Its comfortable 1.46% described the
# other 40%. Scanning everything shows 4.2%. That is not a regression and
# raising the number is not a loosening: the instrument was mis-calibrated and
# 3% never described this codebase. Ratchet down from 4.3 as the clusters below
# are extracted.
#
# Scope: crate source, minus the integration-test dirs (crates/**/tests).
# Inline `#[cfg(test)]` modules live in the same files as the code they test
# and are counted — test copy-paste is still copy-paste; keeping the scope
# honest is the point. jscpd is pinned (aged >24h per the dependency policy)
# and run through npx so no checked-in node_modules is needed. Node is present
# on every CI runner (the web build uses it) and on dev machines.
#
# --max-lines and --max-size are set high deliberately. jscpd defaults to
# skipping any file over 1000 lines (and over 100kb), silently: it reports a
# comfortable percentage having never opened the biggest files in the tree. It
# had been skipping four of ours — 60% of the source — which is precisely the
# silent no-op this repository forbids. The scanned-source count is asserted
# below so a future default, or a file growing past a limit, fails loudly
# instead of quietly shrinking what is measured.
#
# Portable to bash 3.2 (macOS): runs everywhere, not just CI.

set -euo pipefail
cd "$(dirname "$0")/.."

# Ratchet threshold: max duplicated-line percentage (jscpd --mode strict).
# Lower over time. History: 3.75% → 2.3% (sweep 6, partial scan) → 4.3%
# (sweep 26: first full scan; see above — the earlier figures omitted the four
# largest files) → 3.6% (sweep 27: HTTP prologues became extractors, ChanServ's
# founder gate became one function) → 3.5% (sweep 29: the four bridge
# connect-retry loops became one `run_with_backoff`) → 3.3% (sweep 30: the
# CHATHISTORY column list became one `history_select!`/`history_window!`) →
# 3.1% (sweep 31: the oper-only command gate became `require_oper`, and the
# SASL IDENTIFY/REGISTER label-takes became `take_identify_label`/
# `take_register_label`) → 3.0% (sweep 32: config test `ListenerConfig`
# boilerplate became `listener()`, the ChanServ `*_unavailable` notices
# became `chanserv_deferred_notice`, and the main/subcommand config-load
# became `load_config_or_fail`) → 2.8% (sweep 33: the four most-repeated
# IRC numerics became `ServerState` convenience methods —
# `err_needmoreparams`/`err_nosuchnick`/`err_nosuchchannel`/`err_notonchannel`
# (43 call sites across 9 handler files); the bouncer client's
# read-feed-extend loop became `fill()`; the MONITOR watcher-removal loop
# became `unmonitor()`; and the cross-file contact-email validation became
# `parse_optional_contact_email()`) → 2.6% (sweep 34: the unauthenticated
# HTTP pool guard became `require_pool!` (10 sites), ban mutations became
# `ServerBanMutation::add`/`remove` constructors, CAP negotiation marking
# became `mark_negotiating`, SASL payload guards became
# `require_cred_payload`, the labeled FAIL/BATCH prefix became
# `with_label`, the JSON+no-store response became `json_no_store`,
# OIDC client discovery became `discover_client_or_bad_gateway`, and the
# pending-topic cleanup became `clear_pending_topic`) → 2.1% (sweep 35:
# the bridge drivers' `start`/`run`/ws-open/frame-read/http-client
# scaffolding became shared `bridge_*` helpers and macros, the console
# form parse+actor prologues became `account_form_actor`/`admin_form_actor`
# over a macro-generated `AccountForm` impl set, the BNC registry and
# managed-config guards became `require_registry!`/`require_managed_config!`,
# the network/audit/OIDC JSON builders became shared fragments, the account
# INSERT became `insert_account`, the credential-revocation transactions
# became `delete_scoped_credential`, the DB offload spawns became
# `spawn_db_offload`, the ChanServ registered gate split out of the founder
# gate, the message Delivery/HistoryEntry construction hoisted out of the
# channel/DM branch, and the OpenAPI cursor/confirmation fragments became
# shared values) → 1.8% (sweep 36: the admin ban/channel handlers became
# one `admin_policy_form`, the credential-revocation handlers became
# `console_revoke_owned`, the console GET handlers route through `page_actor`,
# the lifecycle error map became `authority_error_status`, the session-token
# lookups became a `session_lookup!` macro, the password-mutation prologue
# became `begin_password_mutation`, the services identify-guard became
# `require_identified`, the channel lookup became `require_channel`, the
# FAIL line builders became `fail_line`, the render-private/render-auth
# envelope became `render_with_security_headers`, the SASL loop terminal
# check became `sasl_terminal_error`, the join-refusal numeric set moved
# from the CLI to the client crate, the LineEvent drain became `push_framed`,
# and the bridge-oracle Slack gate became `slack_gate`).
#
# What is left is mostly sqlx builder chains — `.bind().execute().await
# .map_err()` — and per-route response shaping. Those are plumbing: abstracting
# them would read worse than the repetition, so the number is expected to sit
# here rather than keep falling. Lower it only when a real shared concept is
# found, not by wrapping boilerplate to move a metric.
THRESHOLD=1.9
JSCPD_VERSION=4.0.5

echo "duplication guard: scanning crate source (jscpd@${JSCPD_VERSION}, threshold ${THRESHOLD}%) ..."

# --mode strict counts every clone; --threshold makes jscpd exit non-zero when
# the duplicated-line percentage is above THRESHOLD. Rust tokenizer via
# --formats-exts. Integration-test dirs, build output, and vendored trees are
# excluded; inline unit-test modules are not (they can't be, and shouldn't be).
# Every .rs file jscpd is expected to open, so a silently-skipped one is caught.
EXPECTED=$(find crates -name '*.rs' \
	-not -path '*/tests/*' -not -path '*/benches/*' \
	-not -path '*/fuzz/*' -not -path '*/target/*' | wc -l | tr -d ' ')
REPORT_DIR=$(mktemp -d)
trap 'rm -rf "${REPORT_DIR}"' EXIT

if npx --yes "jscpd@${JSCPD_VERSION}" crates \
	--formats-exts "rust:rs" \
	--min-tokens 50 \
	--max-lines 100000 \
	--max-size "5mb" \
	--threshold "${THRESHOLD}" \
	--ignore "**/tests/**,**/benches/**,**/fuzz/**,**/target/**" \
	--mode strict \
	--reporters console,json \
	--output "${REPORT_DIR}" \
	--silent; then
	SCANNED=$(node -e 'const r=require(process.argv[1]);
const f=(r.statistics&&r.statistics.formats&&r.statistics.formats.rust)||{};
process.stdout.write(String(Object.keys(f.sources||{}).length));' \
		"${REPORT_DIR}/jscpd-report.json")
	if [ "${SCANNED}" -lt "${EXPECTED}" ]; then
		echo "duplication guard FAILED: jscpd scanned ${SCANNED} of ${EXPECTED} source files." >&2
		echo "Files are being skipped (jscpd skips large ones by default), so the" >&2
		echo "percentage above describes only part of the tree. Raise --max-lines/" >&2
		echo "--max-size until every file is scanned." >&2
		exit 1
	fi
	echo "duplication guard: clean (≤ ${THRESHOLD}% duplicated lines, ${SCANNED} files scanned)"
else
	echo "duplication guard FAILED: duplication exceeds ${THRESHOLD}%." >&2
	echo "Extract the shared logic (don't raise the threshold). To see the clones:" >&2
	echo "  npx jscpd@${JSCPD_VERSION} crates --formats-exts rust:rs --min-tokens 50 \\" >&2
	echo "    --ignore '**/tests/**,**/benches/**,**/fuzz/**,**/target/**' --reporters html --output /tmp/jscpd" >&2
	exit 1
fi
