#!/usr/bin/env python3
"""Reject parallel console mutation routes."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
ROUTER = ROOT / "crates" / "e6ircd" / "src" / "http" / "mod.rs"
def console_mutations(source: str) -> set[str]:
    # Router calls are a fluent chain, one `.route` call per line.  Stop at
    # the next call rather than trying to parse nested Rust parentheses.
    routes = re.findall(
        r'\.route\(\s*"(?P<path>/console[^\"]+)"\s*,(?P<body>.*?)'
        r'(?=\n\s*\.route\(|\n\s*;)',
        source,
        re.DOTALL,
    )
    return {
        path
        for path, body in routes
        if re.search(r'\bpost\(', body)
    }


def main() -> int:
    router_paths = console_mutations(ROUTER.read_text(encoding="utf-8"))
    if router_paths:
        for path in sorted(router_paths):
            print(f"parallel console mutation route: {path}", file=sys.stderr)
        return 1
    print("api-first console boundary: clean (no parallel console mutations)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
