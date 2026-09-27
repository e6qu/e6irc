#!/usr/bin/env python3
"""Contract for check-terminology.py: an abbreviation in prose is defined in
the glossary or reported; code, known protocol words, and vendored files are
not prose."""

import importlib.util
import pathlib
import tempfile
import unittest

TOOL = pathlib.Path(__file__).resolve().parent / "check-terminology.py"
spec = importlib.util.spec_from_file_location("check_terminology", TOOL)
terminology = importlib.util.module_from_spec(spec)
spec.loader.exec_module(terminology)

GLOSSARY = (
    "# Terminology\n\n"
    "**Transport Layer Security (TLS)** — encrypted transport.\n\n"
    "**Bouncer / BNC** — an always-on proxy.\n\n"
    "**MOTD** — the banner.\n"
)


class UndefinedAbbreviations(unittest.TestCase):
    def found(self, files: dict[str, str]) -> dict[str, list[str]]:
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            for name, text in {"docs/terminology.md": GLOSSARY, **files}.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            return terminology.undefined_abbreviations(root)

    def test_an_undefined_abbreviation_in_prose_is_reported_where_it_is_used(self):
        found = self.found({"docs/guide.md": "Intro.\n\nThe QZX layer, then QZX again.\n"})
        self.assertEqual(found, {"QZX": ["docs/guide.md:3", "docs/guide.md:3"]})

    def test_every_bold_spelling_in_the_glossary_defines_its_abbreviation(self):
        found = self.found({"README.md": "TLS to the BNC, which sends the MOTD.\n"})
        self.assertEqual(found, {})

    def test_code_is_not_prose(self):
        found = self.found(
            {
                "README.md": (
                    "Set `QZX_MODE` or `QZX`, wrapped `over the\nQZX line`.\n"
                    "```\nQZX in a fenced block\n```\n"
                    "[a link](https://example.com/QZX) and https://example.com/QZX\n"
                ),
                "crates/a/src/lib.rs": 'const QZX: &str = "QZX";\n',
            }
        )
        self.assertEqual(found, {})

    def test_a_code_comment_is_prose(self):
        found = self.found(
            {
                "crates/a/src/lib.rs": 'let x = "QZX"; // the QZX path\n/* QZX block */\n',
                # The shell comment is spelled with chr(35) so this file's own
                # comment scan does not read it as one.
                "tools/run.sh": "echo QZX " + chr(35) + " sends QZX\n",
                "tools/schema.sql": "SELECT 1; -- QZX\n",
            }
        )
        self.assertEqual(
            found,
            {
                "QZX": [
                    "crates/a/src/lib.rs:1",
                    "crates/a/src/lib.rs:2",
                    "tools/run.sh:1",
                    "tools/schema.sql:1",
                ]
            },
        )

    def test_protocol_words_code_points_and_compounds(self):
        found = self.found(
            {
                "DESIGN.md": (
                    "A JOIN or PRIVMSG, U+FFFD and C0, `SHA`. A QZX-terminated link.\n"
                )
            }
        )
        self.assertEqual(found, {"QZX": ["DESIGN.md:1"]})

    def test_vendored_built_and_migration_files_are_not_prose_to_change(self):
        found = self.found(
            {
                "vendor/x/README.md": "QZX\n",
                "web/node_modules/y/README.md": "QZX\n",
                "target/debug/z.md": "QZX\n",
                # A migration is checksum-pinned history.
                "migrations/0001_a.sql": "-- QZX\n",
            }
        )
        self.assertEqual(found, {})


if __name__ == "__main__":
    unittest.main()
