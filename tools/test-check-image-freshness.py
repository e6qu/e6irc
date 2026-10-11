#!/usr/bin/env python3
"""Contract test for tools/check-image-freshness.py, without the network: pins
are found with the Docker Hub repository they copy, a newer release keeps the
variant and the major version, and a newer digest or release is held for 24
hours and then fails, as does a mirror serving another digest."""

from __future__ import annotations

import datetime as dt
import importlib.util
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("freshness", ROOT / "tools/check-image-freshness.py")
assert spec is not None and spec.loader is not None
freshness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(freshness)

NOW = freshness.timestamp("2026-10-11T12:00:00Z")
OLD = NOW - dt.timedelta(hours=24)
YOUNG = OLD + dt.timedelta(microseconds=1)
PINNED = "sha256:" + "a" * 64
MOVED = "sha256:" + "b" * 64
failures: list[str] = []


def expect(name: str, actual: object, wanted: object) -> None:
    if actual != wanted:
        failures.append(f"{name}: got {actual!r}, wanted {wanted!r}")


found = freshness.pins(
    [
        ("Dockerfile", f"FROM public.ecr.aws/docker/library/example:1.2.3-bookworm@{PINNED} AS build"),
        ("ci.yml", f"driver-opts: image=mirror.gcr.io/someone/tool:v0.4.0@{PINNED}"),
        ("other.yml", "image: public.ecr.aws/docker/library/example:2-alpine"),
    ]
)
expect(
    "pins name the Docker Hub repository they copy, and skip unpinned references",
    set(found),
    {
        ("public.ecr.aws/docker/library", "example", "library/example", "1.2.3-bookworm", PINNED),
        ("mirror.gcr.io", "someone/tool", "someone/tool", "v0.4.0", PINNED),
    },
)

candidates = [
    ("1.2.4-bookworm", OLD),
    ("1.2.4-alpine", OLD),
    ("1.3.0-bookworm", OLD),
    ("2.0.0-bookworm", OLD),
    ("1.2-bookworm", OLD),
    ("1.2.2-bookworm", OLD),
]
expect(
    "newer releases keep the variant and the major version",
    [tag for tag, _ in freshness.newer_releases("1.2.3-bookworm", candidates)],
    ["1.3.0-bookworm", "1.2.4-bookworm"],
)
expect("a tag that is not a version has no newer release", freshness.newer_releases("bullseye-slim", candidates), [])
expect(
    "a `v` prefix is part of the version's form",
    [tag for tag, _ in freshness.newer_releases("v0.4.0", [("v0.5.0", OLD), ("0.6.0", OLD)])],
    ["v0.5.0"],
)

expect("current pin served by the mirror", freshness.verdict(PINNED, PINNED, OLD, PINNED, [], NOW), ("ok", []))
expect("moved tag inside 24 hours", freshness.verdict(PINNED, MOVED, YOUNG, PINNED, [], NOW)[0], "HELD")
expect("moved tag after 24 hours", freshness.verdict(PINNED, MOVED, OLD, PINNED, [], NOW)[0], "DRIFT")
expect("newer release inside 24 hours", freshness.verdict(PINNED, PINNED, OLD, PINNED, [("1.2.4", YOUNG)], NOW)[0], "HELD")
expect("newer release after 24 hours", freshness.verdict(PINNED, PINNED, OLD, PINNED, [("1.2.4", OLD)], NOW)[0], "DRIFT")
expect("mirror serving another digest", freshness.verdict(PINNED, PINNED, OLD, MOVED, [], NOW)[0], "DRIFT")

if failures:
    print("image-freshness contract FAILED:", file=sys.stderr)
    for failure in failures:
        print(f"  {failure}", file=sys.stderr)
    sys.exit(1)
print("image-freshness contract: clean")
