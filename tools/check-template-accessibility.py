#!/usr/bin/env python3
"""Reject structural accessibility regressions in server-rendered HTML and in
the markup the console script generates."""

from html.parser import HTMLParser
from pathlib import Path
import re
import sys


ROOT = Path(__file__).resolve().parents[1]
TEMPLATES = ROOT / "crates" / "e6ircd" / "templates"
WEB_ENTRY = ROOT / "web" / "index.html"


class TemplateParser(HTMLParser):
    def __init__(self, path: Path) -> None:
        super().__init__(convert_charrefs=True)
        self.path = path
        self.table_lines: list[int] = []
        self.table_has_caption: list[bool] = []
        self.label_depth = 0
        self.ids: dict[str, int] = {}
        self.errors: list[str] = []

    def handle_starttag(
        self, tag: str, attrs: list[tuple[str, str | None]]
    ) -> None:
        attributes = dict(attrs)
        element_id = attributes.get("id")
        if element_id:
            if element_id in self.ids:
                self.errors.append(
                    f"{self.path.relative_to(ROOT)}:{self.getpos()[0]}: "
                    f'duplicate id "{element_id}" (first used on line {self.ids[element_id]})'
                )
            else:
                self.ids[element_id] = self.getpos()[0]
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


CONSOLE_SCRIPT = ROOT / "crates" / "e6ircd" / "assets" / "console.js"

# The console builds much of its markup at runtime, out of this parser's reach.
# Its accessibility contract lives in a few builders instead: a form control, a
# table or an accessible name may be created only inside them, and each one
# requires what the template rules above require (a label or aria-label, a
# caption, a role before a name). So the rule for the script is where those
# things may be made, which a line-level scan can check.
CONSOLE_BUILDERS = {
    "element",  # generic; refused for the tags below by the literal rule
    "ariaName",
    "hiddenInput",
    "namedControl",
    "labelledControl",
    "captionedTable",
}
BUILDER_START = re.compile(r"^(\s*)const (\w+) = \(")
RESTRICTED_LITERAL = re.compile(
    r"""(?:createElement|\belement)\(\s*["'](input|select|textarea|table)["']"""
)
VARIABLE_TAG = re.compile(r"createElement\(\s*[A-Za-z_]\w*\s*\)")
NAMING = re.compile(r"""setAttribute\(\s*["']aria-label["']|\.ariaLabel\s*=""")
RAW_MARKUP = re.compile(r"\b(?:innerHTML|outerHTML|insertAdjacentHTML)\b")


def console_builder_lines(lines: list[str]) -> dict[int, str]:
    """Map each line inside an approved builder's body to that builder."""
    owners: dict[int, str] = {}
    index = 0
    while index < len(lines):
        match = BUILDER_START.match(lines[index])
        if match and match.group(2) in CONSOLE_BUILDERS:
            indent, name = match.group(1), match.group(2)
            # A builder's body ends at the first `};` at its own indentation.
            end = index + 1
            while end < len(lines) and lines[end].rstrip() != f"{indent}}};":
                end += 1
            if end == len(lines):
                raise SystemExit(f"{CONSOLE_SCRIPT}: builder {name} never ends")
            for line in range(index, end + 1):
                owners[line] = name
            index = end + 1
            continue
        index += 1
    return owners


def check_console_script() -> list[str]:
    errors: list[str] = []
    lines = CONSOLE_SCRIPT.read_text(encoding="utf-8").splitlines()
    owners = console_builder_lines(lines)
    where = CONSOLE_SCRIPT.relative_to(ROOT)
    for index, line in enumerate(lines):
        owner = owners.get(index)
        number = index + 1
        match = RESTRICTED_LITERAL.search(line)
        if match and owner in (None, "element"):
            errors.append(
                f"{where}:{number}: a generated <{match.group(1)}> must come from "
                "hiddenInput, namedControl, labelledControl or captionedTable"
            )
        if VARIABLE_TAG.search(line) and owner not in {"element", "namedControl", "labelledControl"}:
            errors.append(
                f"{where}:{number}: an element whose tag is a variable escapes the "
                "builder rules; name the tag, or use a builder"
            )
        if NAMING.search(line) and owner != "ariaName":
            errors.append(
                f"{where}:{number}: an accessible name must be set through ariaName, "
                "which refuses a generic element without a role"
            )
        if RAW_MARKUP.search(line):
            errors.append(
                f"{where}:{number}: markup assembled from a string escapes the builder rules"
            )
    for name in CONSOLE_BUILDERS:
        if name not in owners.values():
            errors.append(f"{where}: the builder {name} is missing")
    errors.extend(check_startup_bindings(lines))
    return errors


STARTUP_LOOP = re.compile(r"""for \(const \w+ of document\.querySelectorAll\(["']\[(data-[\w-]+)\]["']\)\)""")
GENERATED_MARKER = re.compile(r"\.dataset\.(\w+)\s*=")


def check_startup_bindings(lines: list[str]) -> list[str]:
    """A listener bound at startup reaches only the elements that exist then.

    So a startup loop's selector must be one a template renders, and not one
    the script itself generates later: a form built after an API read and
    handled only by a startup loop is submitted natively by the browser. Rows
    the script builds are handled by delegated listeners on `document`.
    """
    errors: list[str] = []
    where = CONSOLE_SCRIPT.relative_to(ROOT)
    templates = "\n".join(
        path.read_text(encoding="utf-8") for path in sorted(TEMPLATES.glob("*.html"))
    )
    generated = {
        "data-" + re.sub(r"[A-Z]", lambda upper: "-" + upper.group(0).lower(), match.group(1))
        for line in lines
        for match in GENERATED_MARKER.finditer(line)
    }
    for index, line in enumerate(lines):
        for match in STARTUP_LOOP.finditer(line):
            attribute = match.group(1)
            if not re.search(rf"\b{re.escape(attribute)}\b(?![\w-])", templates):
                errors.append(
                    f"{where}:{index + 1}: startup binding for [{attribute}], which no "
                    "template renders (dead, or generated later and never bound)"
                )
            elif attribute in generated:
                errors.append(
                    f"{where}:{index + 1}: startup binding for [{attribute}], which the "
                    "script also generates; delegate it from document instead"
                )
    return errors


def main() -> int:
    errors: list[str] = check_console_script()
    files = [WEB_ENTRY, *sorted(TEMPLATES.glob("*.html"))]
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
        f"({len(files) - 1} server-rendered templates, the web application shell, "
        f"and the console script's generated markup)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
