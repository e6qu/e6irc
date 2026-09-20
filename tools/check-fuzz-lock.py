#!/usr/bin/env python3
"""Keep fuzz/Cargo.lock on the workspace's dependency versions.

`fuzz/` is its own package outside the workspace, so it resolves its own lock.
Left alone the two drift, and the fuzz targets then exercise a different tokio,
hyper, or serde than the daemon that ships. Every crate the two locks share
must be locked in `fuzz/` at a version the workspace lock also has.

To realign after a workspace lock change:

    cp Cargo.lock fuzz/Cargo.lock
    cargo metadata --manifest-path fuzz/Cargo.toml --format-version 1 >/dev/null

Cargo keeps every entry that still applies, drops the rest, and adds the
fuzz-only crates; then check that those (listed below by this script) did not
move unintentionally.
"""

from __future__ import annotations

import collections
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = re.compile(r'\[\[package\]\]\nname = "([^"]+)"\nversion = "([^"]+)"')


def locked(path: pathlib.Path) -> dict[str, set[str]]:
    versions: dict[str, set[str]] = collections.defaultdict(set)
    for name, version in PACKAGE.findall(path.read_text(encoding="utf-8")):
        versions[name].add(version)
    return versions


def main() -> int:
    workspace = locked(ROOT / "Cargo.lock")
    fuzz = locked(ROOT / "fuzz" / "Cargo.lock")
    if not workspace or not fuzz:
        print("fuzz-lock guard: a lock file has no packages; nothing was compared", file=sys.stderr)
        return 1
    shared = sorted(set(workspace) & set(fuzz))
    if not shared:
        print("fuzz-lock guard: the locks share no crate; nothing was compared", file=sys.stderr)
        return 1
    drifted = [name for name in shared if not fuzz[name] <= workspace[name]]
    for name in drifted:
        print(
            f"fuzz-lock guard: {name} is locked at {', '.join(sorted(fuzz[name]))} in "
            f"fuzz/Cargo.lock but {', '.join(sorted(workspace[name]))} in Cargo.lock",
            file=sys.stderr,
        )
    if drifted:
        print(f"fuzz-lock guard FAILED ({len(drifted)} drifted; see {__file__})", file=sys.stderr)
        return 1
    only = sorted(set(fuzz) - set(workspace))
    print(f"fuzz-lock guard: clean ({len(shared)} shared crates; fuzz-only: {', '.join(only)})")
    return 0


if __name__ == "__main__":
    sys.exit(main())
