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


METHODS = r"GET|POST|PUT|PATCH|DELETE"
URL_LITERAL = r'["`](/api/v1[^"`\n]*)["`]'
CALL_SITE = re.compile(
    r"\b(?:apiMutation|apiOperation)\((?P<args>[^()]*(?:\([^()]*\)[^()]*)*)\)"
)
# The shapes in which console.js states a method and a URL together.
DIRECT_OPERATION = re.compile(
    rf'\b(?:apiMutation|apiOperation)\(\s*"({METHODS})"\s*,\s*{URL_LITERAL}\s*\)'
)
NAMED_URL_OPERATION = re.compile(
    rf'\b(?:apiMutation|apiOperation)\(\s*"({METHODS})"\s*,\s*([A-Za-z_$][\w$]*)\s*\)'
)
WRAPPED_OPERATION = re.compile(rf'{URL_LITERAL}\s*,\s*"({METHODS})"')
READ_OPERATION = re.compile(rf"\bapiRead\(\s*{URL_LITERAL}")

# A wrapper whose method is fixed in its body and whose URL is its second
# argument: `WRAPPER(form, URL, ...)` is that method on URL.
FIXED_METHOD_WRAPPERS = {"mutateSession": "DELETE"}

# A `${...}` that stands for one of a closed set of literal path segments
# rather than for a route parameter. Each value must still appear, quoted, in
# console.js, so renaming one there fails here.
SEGMENT_VARIABLES = {"route": ("networks", "opers", "oidc-providers")}

# `/api/v1` literals that are not request URLs.
NON_ROUTE_LITERALS = {
    "/api/v1/": "the prefix apiOperation requires of every URL before it is sent",
}

# apiMutation/apiOperation call sites whose method or URL is not a literal at
# the call, as `arguments: (count, reason)`. The count is exact, so a new site
# of the same shape fails the gate until its operation is accounted for here.
UNRESOLVED_CALL_SITES = {
    '"GET", url': (1, "the body of apiRead; every apiRead(URL) is checked as GET"),
    '"DELETE", url': (1, "the body of mutateSession; see FIXED_METHOD_WRAPPERS"),
    "method, url": (
        4,
        "the bodies of mutateConfiguration, mutateBan, mutateOwnerNetwork and "
        "mutateChannel; each caller's literal URL and method are checked as a pair",
    ),
    "method, form.action": (
        2,
        "the bodies of mutateAccount and mutateAdminAccount; the URL is a "
        "template form action, which is checked against the mutating routes",
    ),
    '"PATCH", form.action': (
        1,
        "the administrator network toggle, whose form console.js builds with the "
        "literal action /api/v1/admin/networks/{owner}/{name}, checked as a path",
    ),
}


def normalized_path(url: str) -> list[str]:
    """The documented-route spellings a console URL literal can stand for."""

    path = url.split("?", 1)[0]
    # `...audit${window.location.search}`: glued to a segment, it is the query.
    path = re.sub(r"(?<=[^/])\$\{[^}]*\}$", "", path)
    paths = [path]
    for variable, values in SEGMENT_VARIABLES.items():
        marker = "/${" + variable + "}"
        paths = [
            candidate.replace(marker, "/" + value) if marker in candidate else candidate
            for candidate in paths
            for value in (values if marker in candidate else ("",))
        ]
    return [re.sub(r"\$\{[^}]*\}", "{param}", candidate) for candidate in paths]


def route_pattern(path: str) -> str:
    return re.sub(r"\{[^}]*\}", "{param}", path)


def named_url(source: str, position: int, name: str) -> str | None:
    """The literal a `const NAME = URL;` just above `position` binds, if any."""

    preceding = source[:position].splitlines()[-12:]
    for line in reversed(preceding):
        if re.search(rf"\(([^()]*\b)?{re.escape(name)}\b[^()]*\)\s*=>", line):
            return None  # NAME is a parameter here, not a local literal.
        bound = re.search(rf"\bconst {re.escape(name)} = {URL_LITERAL};", line)
        if bound:
            return bound.group(1)
    return None


def console_operations(source: str, errors: list[str]) -> set[tuple[str, str]]:
    """Every (method, URL) pair console.js states, and every call it does not."""

    operations: set[tuple[str, str]] = set()
    resolved_sites: set[int] = set()
    for match in DIRECT_OPERATION.finditer(source):
        operations.add((match.group(1), match.group(2)))
        resolved_sites.add(match.start())
    for match in NAMED_URL_OPERATION.finditer(source):
        url = named_url(source, match.start(), match.group(2))
        if url is not None:
            operations.add((match.group(1), url))
            resolved_sites.add(match.start())
    for match in WRAPPED_OPERATION.finditer(source):
        operations.add((match.group(2), match.group(1)))
    for match in READ_OPERATION.finditer(source):
        operations.add(("GET", match.group(1)))
    for wrapper, method in FIXED_METHOD_WRAPPERS.items():
        callers = re.finditer(rf"\b{wrapper}\(\s*[\w$]+\s*,\s*{URL_LITERAL}", source)
        operations.update((method, caller.group(1)) for caller in callers)

    unresolved: dict[str, int] = {}
    for site in CALL_SITE.finditer(source):
        if site.start() not in resolved_sites:
            arguments = " ".join(site.group("args").split())
            unresolved[arguments] = unresolved.get(arguments, 0) + 1
    for arguments in sorted(set(unresolved) | set(UNRESOLVED_CALL_SITES)):
        expected = UNRESOLVED_CALL_SITES.get(arguments, (0, ""))[0]
        found = unresolved.get(arguments, 0)
        if found != expected:
            errors.append(
                f"console.js has {found} operation call(s) of the form "
                f"apiMutation({arguments}) that cannot be checked statically; "
                f"{expected} are accounted for in UNRESOLVED_CALL_SITES"
            )
    return operations


def check_console_contract(source: str, router: str, templates) -> list[str]:
    """Match what console.js and its forms request against the route table."""

    errors: list[str] = []
    documented = {
        (route_pattern(path), method) for path, method in documented_operations(router)
    }
    documented_paths = {path for path, _ in documented}
    mutating_paths = {path for path, method in documented if method != "GET"}
    if not documented:
        errors.append("no documented /api/v1 operation was found in the router")

    operations = console_operations(source, errors)
    if not operations:
        errors.append("no console operation was extracted: this check would be vacuous")
    for method, url in sorted(operations):
        if not any((path, method) in documented for path in normalized_path(url)):
            errors.append(
                f"console operation is absent from the public API contract: {method} {url}"
            )
        elif len(normalized_path(url)) > 1:
            for path in normalized_path(url):
                if (path, method) not in documented:
                    errors.append(
                        f"console operation is absent from the public API contract: "
                        f"{method} {path} (from {url})"
                    )

    for url in sorted(set(re.findall(URL_LITERAL, source))):
        if url in NON_ROUTE_LITERALS:
            continue
        for path in normalized_path(url):
            if path not in documented_paths:
                errors.append(f"console URL is not a documented API route: {url}")
    for literal in sorted(NON_ROUTE_LITERALS):
        if f'"{literal}"' not in source:
            errors.append(f"NON_ROUTE_LITERALS names {literal}, which console.js no longer has")
    for variable, values in SEGMENT_VARIABLES.items():
        for value in values:
            if f'"{value}"' not in source:
                errors.append(
                    f'SEGMENT_VARIABLES gives ${{{variable}}} the value "{value}", '
                    "which console.js no longer names"
                )

    for template, form in templates:
        action = form.get("action", "")
        if api_markers(form) and action.startswith("/api/v1/"):
            if route_pattern(re.sub(r"\{\{[^}]*\}\}", "{param}", action)) not in mutating_paths:
                errors.append(
                    f"console form posts to a route with no documented mutation: "
                    f"{template.name}: {action}"
                )
    return errors


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

    for error in check_console_contract(
        asset, ROUTER.read_text(encoding="utf-8"), template_mutations()
    ):
        print(error, file=sys.stderr)
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
