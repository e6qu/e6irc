#!/usr/bin/env python3
"""Reject structural accessibility regressions in server-rendered HTML."""

from html.parser import HTMLParser
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "crates" / "e6ircd" / "templates"


class TemplateParser(HTMLParser):
    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.table_lines: list[int] = []
        self.table_has_caption: list[bool] = []
        self.label_depth = 0
        self.errors: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        if tag == "table":
            self.table_lines.append(self.getpos()[0])
            self.table_has_caption.append(False)
        elif tag == "caption" and self.table_has_caption:
            self.table_has_caption[-1] = True
        elif tag == "nav" and not (
            attributes.get("aria-label") or attributes.get("aria-labelledby")
        ):
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: "
                "navigation landmark has no accessible name"
            )
        elif tag == "div" and "scroll" in attributes.get("class", "").split():
            if (
                attributes.get("tabindex") != "0"
                or attributes.get("role") != "region"
                or not attributes.get("aria-label")
            ):
                self.errors.append(
                    f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: "
                    "scroll region must be focusable, named, and carry region semantics"
                )
        elif (
            tag in {"div", "span"}
            and (attributes.get("aria-label") or attributes.get("aria-labelledby"))
            and not attributes.get("role")
        ):
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: "
                "generic element with an accessible name must declare valid semantics"
            )
        elif tag == "label":
            self.label_depth += 1
        elif tag in {"input", "select", "textarea"}:
            if attributes.get("type") == "hidden":
                return
            if self.label_depth or any(
                attributes.get(name) for name in ("aria-label", "aria-labelledby", "title")
            ):
                return
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: "
                "form control has no accessible name"
            )
        elif tag == "img" and "alt" not in attributes:
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: image has no alt text"
            )
        elif tag == "dialog" and not (
            attributes.get("aria-label") or attributes.get("aria-labelledby")
        ):
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: dialog has no accessible name"
            )

    def handle_endtag(self, tag: str) -> None:
        if tag == "label":
            self.label_depth -= 1
            return
        if tag != "table" or not self.table_lines:
            return
        line = self.table_lines.pop()
        has_caption = self.table_has_caption.pop()
        if not has_caption:
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{line}: table has no caption"
            )

    def finish(self) -> list[str]:
        for line in self.table_lines:
            self.errors.append(
                f"{self.path.relative_to(ROOT)}:{line}: table is not closed"
            )
        return self.errors


def main() -> int:
    errors: list[str] = []
    files = sorted(TEMPLATES.glob("*.html"))
    for path in files:
        parser = TemplateParser(path)
        source = path.read_text(encoding="utf-8")
        try:
            parser.feed(source)
            parser.close()
        except Exception as error:
            errors.append(f"{path.relative_to(ROOT)}: parse failed: {error}")
        errors.extend(parser.finish())
        for match in re.finditer(r"<th(?:\s[^>]*)?>\s*</th>", source):
            line = source.count("\n", 0, match.start()) + 1
            errors.append(
                f"{path.relative_to(ROOT)}:{line}: table header has no accessible name"
            )
    if errors:
        print("\n".join(errors), file=sys.stderr)
        return 1
    print(
        f"template accessibility guard: clean "
        f"({len(files)} server-rendered templates)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
