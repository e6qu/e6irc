#!/usr/bin/env bash
# An SPDX SBOM of the e6ircd image must name the Rust crates compiled into the
# binary (the Dockerfile builds it with `cargo auditable`, which embeds them).
# `rustls` is the witness: every build links it, and an SBOM that lacks it
# lists only the base image's system packages, which is no basis for a RUSTSEC
# scan. Usage: tools/check-sbom-rust-crates.sh <sbom.spdx.json>
set -euo pipefail

sbom="${1:?usage: $0 <sbom.spdx.json>}"
if ! jq -e '[.packages[]? | select(.name == "rustls")] | length > 0' "$sbom" >/dev/null; then
  echo "$sbom names no rustls package: the SBOM does not list the binary's Rust crates (is it built with cargo auditable?)" >&2
  exit 1
fi
crates="$(jq '[.packages[]? | select((.externalRefs // []) | any(.referenceLocator | startswith("pkg:cargo/")))] | length' "$sbom")"
echo "$sbom lists $crates Rust crates, rustls among them"
