#!/usr/bin/env python3
"""Keep the published client capability matrix aligned with code."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
DOCUMENT = ROOT / "docs" / "client-capabilities.md"
BNC_SOURCE = ROOT / "crates" / "e6ircd" / "src" / "bouncer" / "serve.rs"
CLI_SOURCE = ROOT / "crates" / "e6irc-cli" / "src" / "main.rs"
TUI_SOURCE = ROOT / "crates" / "e6irc-tui" / "src" / "main.rs"


def fail(message: str) -> int:
    print(f"client-capability guard: {message}", file=sys.stderr)
    return 1


def quoted_values(source: str, pattern: str) -> list[str]:
    match = re.search(pattern, source, re.DOTALL)
    if match is None:
        raise ValueError(f"missing source pattern {pattern!r}")
    return re.findall(r'"([^"]+)"', match.group(1))


def main() -> int:
    document = DOCUMENT.read_text(encoding="utf-8")
    bnc_source = BNC_SOURCE.read_text(encoding="utf-8")
    cli_source = CLI_SOURCE.read_text(encoding="utf-8")
    tui_source = TUI_SOURCE.read_text(encoding="utf-8")

    published = re.search(r"^\*\*BNC attach CAP LS:\*\* `([^`]+)`$", document, re.MULTILINE)
    if published is None:
        return fail("missing BNC attach CAP LS declaration")
    source_caps = re.findall(r'Self::\w+ => "([^"]+)",', bnc_source)
    if published.group(1).split() != source_caps:
        return fail("BNC attach CAP LS differs from AttachCapability")

    cli_caps = quoted_values(
        cli_source,
        r"require_capabilities\(&\[(.*?)\]\)",
    )
    if "`history` requires `" + " ".join(cli_caps) + "`" not in document:
        return fail("CLI history requirement differs from the matrix")

    tui_caps = quoted_values(tui_source, r"capabilities\.extend\(\[(.*?)\]\)")
    marker = "Requires `" + " ".join(tui_caps) + "`"
    if marker not in document:
        return fail("TUI history requirement differs from the matrix")
    if 'capabilities.push("draft/read-marker")' not in tui_source:
        return fail("TUI read-marker requirement is not explicit")
    if "requires `draft/read-marker` unless disabled" not in document:
        return fail("TUI read-marker boundary differs from the matrix")

    print("client-capability guard: clean")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        raise SystemExit(f"client-capability guard: {error}")
