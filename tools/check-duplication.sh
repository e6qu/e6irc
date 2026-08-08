#!/usr/bin/env bash
# Copy-paste guard for shipped Rust source. Portable to bash 3.2.

set -euo pipefail
cd "$(dirname "$0")/.."

# Maximum duplicate lines. Lower it only after extracting shared behavior.
THRESHOLD=1.9
JSCPD_VERSION=4.0.5

echo "duplication guard: scanning crate source (jscpd@${JSCPD_VERSION}, threshold ${THRESHOLD}%) ..."

# Scan every shipped Rust source file and assert none were skipped.
EXPECTED=$(find crates -name '*.rs' \
	-not -path '*/tests/*' -not -path '*/benches/*' \
	-not -path '*/fuzz/*' -not -path '*/target/*' | wc -l | tr -d ' ')
REPORT_DIR=$(mktemp -d)
trap '[ -n "${KEEP_DUPLICATION_REPORT:-}" ] || rm -rf "${REPORT_DIR}"' EXIT

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
