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
# largest files) → 3.6% (sweep 27: the HTTP prologues became extractors and
# ChanServ's founder gate became one function). Remaining clusters, in size
# order: the bridge drivers' connect-retry loops, db.rs's per-query row
# mapping, and the remaining http.rs response-shaping.
THRESHOLD=3.6
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
