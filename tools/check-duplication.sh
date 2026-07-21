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
# Scope: crate source, minus the integration-test dirs (crates/**/tests).
# Inline `#[cfg(test)]` modules live in the same files as the code they test
# and are counted — test copy-paste is still copy-paste; keeping the scope
# honest is the point. jscpd is pinned (aged >24h per the dependency policy)
# and run through npx so no checked-in node_modules is needed. Node is present
# on every CI runner (the web build uses it) and on dev machines.
#
# Portable to bash 3.2 (macOS): runs everywhere, not just CI.

set -euo pipefail
cd "$(dirname "$0")/.."

# Ratchet threshold: max duplicated-line percentage (jscpd --mode strict).
# Lower over time. History: 3.75% (sweep 6 start) → 2.3% (sweep 6).
THRESHOLD=3
JSCPD_VERSION=4.0.5

echo "duplication guard: scanning crate source (jscpd@${JSCPD_VERSION}, threshold ${THRESHOLD}%) ..."

# --mode strict counts every clone; --threshold makes jscpd exit non-zero when
# the duplicated-line percentage is above THRESHOLD. Rust tokenizer via
# --formats-exts. Integration-test dirs, build output, and vendored trees are
# excluded; inline unit-test modules are not (they can't be, and shouldn't be).
if npx --yes "jscpd@${JSCPD_VERSION}" crates \
	--formats-exts "rust:rs" \
	--min-tokens 50 \
	--threshold "${THRESHOLD}" \
	--ignore "**/tests/**,**/benches/**,**/fuzz/**,**/target/**" \
	--mode strict \
	--reporters console \
	--silent; then
	echo "duplication guard: clean (≤ ${THRESHOLD}% duplicated lines)"
else
	echo "duplication guard FAILED: duplication exceeds ${THRESHOLD}%." >&2
	echo "Extract the shared logic (don't raise the threshold). To see the clones:" >&2
	echo "  npx jscpd@${JSCPD_VERSION} crates --formats-exts rust:rs --min-tokens 50 \\" >&2
	echo "    --ignore '**/tests/**,**/benches/**,**/fuzz/**,**/target/**' --reporters html --output /tmp/jscpd" >&2
	exit 1
fi
