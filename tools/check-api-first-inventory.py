#!/usr/bin/env python3
"""Enforce the console's public API boundary."""

from html.parser import HTMLParser
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
ROUTER = ROOT / "crates" / "e6ircd" / "src" / "http" / "mod.rs"
ASSET = ROOT / "crates" / "e6ircd" / "assets" / "console.js"
TEMPLATES = ROOT / "crates" / "e6ircd" / "templates"


class ConsoleForms(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.forms: list[dict[str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "form":
            self.forms.append({key: value or "" for key, value in attrs})
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


def documented_operations(source: str) -> set[tuple[str, str]]:
    routes = re.findall(
        r'^\s*"(?P<path>/api/v1[^\"]+)"\s*=>\s*\{(?P<body>.*?)(?=^\s*"/api/v1|^}\n\npub fn router)',
        source,
        re.MULTILINE | re.DOTALL,
    )
    return {
        (path, method.upper())
        for path, body in routes
        for method in re.findall(r"\b(get|post|put|patch|delete)\s*:", body)
    }


def console_operations(source: str) -> set[tuple[str, str]]:
    routes = re.findall(r'apiRoute\((?P<args>[^)]*)\)', source)
    operations: set[tuple[str, str]] = set()
    for args in routes:
        values = re.findall(r'"([^\"]+)"', args)
        if not values:
            continue
        path, *methods = values
        operations.update((path, method) for method in methods)
    return operations


def uses_only_declared_mutations(source: str) -> bool:
    calls = re.findall(r"apiRequest\((?P<args>[^\n]*)", source)
    return all("apiMutation(" in args for args in calls)


def template_mutations() -> list[tuple[Path, dict[str, str]]]:
    forms: list[tuple[Path, dict[str, str]]] = []
    for template in TEMPLATES.glob("console*.html"):
        parser = ConsoleForms()
        parser.feed(template.read_text(encoding="utf-8"))
        forms.extend((template, form) for form in parser.forms if form.get("method", "get").lower() == "post")
    return forms


def api_markers(form: dict[str, str]) -> list[str]:
    return sorted(key for key in form if key.startswith("data-api-"))


def main() -> int:
    failures = False
    router_paths = console_mutations(ROUTER.read_text(encoding="utf-8"))
    if router_paths:
        for path in sorted(router_paths):
            print(f"parallel console mutation route: {path}", file=sys.stderr)
        failures = True

    asset = ASSET.read_text(encoding="utf-8")
    if "window.location.reload" in asset:
        print("console mutation reload: use an API refresher instead", file=sys.stderr)
        failures = True

    if not uses_only_declared_mutations(asset):
        print("console mutation bypasses the declared operation boundary", file=sys.stderr)
        failures = True

    documented = documented_operations(ROUTER.read_text(encoding="utf-8"))
    for path, method in sorted(console_operations(asset) - documented):
        print(
            f"console mutation is absent from the public API contract: {method} {path}",
            file=sys.stderr,
        )
        failures = True

    for template, form in template_mutations():
        markers = api_markers(form)
        if not markers:
            continue
        action = form.get("action", "")
        if action and not action.startswith("/api/v1/"):
            print(f"console mutation bypasses public API: {template.name}: {action}", file=sys.stderr)
            failures = True
        for marker in markers:
            if marker not in asset:
                print(f"console mutation has no client handler: {template.name}: {marker}", file=sys.stderr)
                failures = True

    if failures:
        return 1
    print("api-first console boundary: clean")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
