#!/usr/bin/env python3
"""Keep the API-first console-mutation inventory aligned with the router."""

from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
ROUTER = ROOT / "crates" / "e6ircd" / "src" / "http" / "mod.rs"
INVENTORY = ROOT / "docs" / "api-first-inventory.md"


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
        if re.search(r'\bpost\(pages::console_', body)
    }


def inventory_mutations(markdown: str) -> set[str]:
    return set(re.findall(r"^\| `(/console[^`]+)` \|", markdown, re.MULTILINE))


def main() -> int:
    router_paths = console_mutations(ROUTER.read_text(encoding="utf-8"))
    inventory_paths = inventory_mutations(INVENTORY.read_text(encoding="utf-8"))
    if not router_paths:
        print("api-first inventory found no console mutations in the router")
        return 0
    missing = sorted(router_paths - inventory_paths)
    stale = sorted(inventory_paths - router_paths)
    if missing or stale:
        for path in missing:
            print(f"api-first inventory missing console mutation: {path}", file=sys.stderr)
        for path in stale:
            print(f"api-first inventory names no router mutation: {path}", file=sys.stderr)
        return 1
    print(f"api-first inventory: clean ({len(router_paths)} console mutations covered)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
