#!/usr/bin/env python3
"""Contract for check-journeys.py's evidence names: a test is evidence, a
production function or an arbitrary quoted word is not."""

import importlib.util
import pathlib
import tempfile
import unittest

TOOL = pathlib.Path(__file__).resolve().parent / "check-journeys.py"
spec = importlib.util.spec_from_file_location("check_journeys", TOOL)
journeys = importlib.util.module_from_spec(spec)
spec.loader.exec_module(journeys)


class EvidenceNames(unittest.TestCase):
    def names_in(self, files: dict[str, str]) -> set[str]:
        with tempfile.TemporaryDirectory() as scratch:
            root = pathlib.Path(scratch)
            for name, text in files.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(text, encoding="utf-8")
            saved = journeys.ROOT
            journeys.ROOT = root
            try:
                return journeys.defined_test_names()
            finally:
                journeys.ROOT = saved

    def test_only_tests_are_evidence(self):
        names = self.names_in(
            {
                "crates/a/src/lib.rs": (
                    "pub fn production_path() {}\n"
                    "#[cfg(test)]\nmod tests {\n"
                    "    #[test]\n    fn unit_case() {}\n"
                    "    fn test_helper() {}\n}\n"
                ),
                "crates/a/tests/it.rs": (
                    '#[tokio::test(flavor = "multi_thread")]\n'
                    '#[ignore = "needs PostgreSQL"]\n'
                    "async fn async_case() {}\n"
                ),
                "web/test/ui.test.js": (
                    'test("browser_case", () => {});\n'
                    'const mode = "not_a_test";\n'
                ),
                "tools/check.py": "def test_python_case():\n    pass\n"
                "def production_helper():\n    pass\n",
            }
        )
        for name in ("unit_case", "async_case", "browser_case", "test_python_case"):
            self.assertIn(name, names)
        for name in ("production_path", "test_helper", "not_a_test", "production_helper"):
            self.assertNotIn(name, names)

    def test_the_repositorys_own_tests_are_found_and_its_functions_are_not(self):
        self.assertIn(
            "sasl_required_of_everyone_refuses_an_anonymous_client_and_admits_a_logged_in_one",
            journeys.defined_test_names(),
        )
        self.assertNotIn("maybe_complete_registration", journeys.defined_test_names())


if __name__ == "__main__":
    unittest.main()
