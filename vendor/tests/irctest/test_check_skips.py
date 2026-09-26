#!/usr/bin/env python3
"""Contract for check_skips.py: a skip missing from the list, a listed test
that no longer skips, and an entry without a reason each fail; a run whose
skips are exactly the list passes."""

import pathlib
import subprocess
import sys
import tempfile
import unittest

CHECK = pathlib.Path(__file__).resolve().parent / "check_skips.py"

REPORT = """<?xml version="1.0" encoding="utf-8"?>
<testsuites><testsuite name="pytest">
<testcase classname="irctest.server_tests.list.ListTestCase" name="testListMask">
  <skipped type="pytest.skip" message="Optional behavior not supported: ELIST_M"/>
</testcase>
<testcase classname="irctest.server_tests.join.JoinTestCase" name="testJoin"/>
</testsuite></testsuites>
"""


class CheckSkips(unittest.TestCase):
    def run_check(self, listing: str) -> subprocess.CompletedProcess:
        with tempfile.TemporaryDirectory() as scratch:
            report = pathlib.Path(scratch, "report.xml")
            report.write_text(REPORT, encoding="utf-8")
            expected = pathlib.Path(scratch, "expected.txt")
            expected.write_text(listing, encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECK), str(report), str(expected)],
                capture_output=True,
                text=True,
            )

    def test_the_listed_skips_pass(self):
        result = self.run_check(
            "# no ELIST\nirctest.server_tests.list.ListTestCase::testListMask\n"
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_an_unlisted_skip_fails_naming_it_and_its_reason(self):
        result = self.run_check("")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ListTestCase::testListMask", result.stderr)
        self.assertIn("ELIST_M", result.stderr)

    def test_a_listed_test_that_now_runs_fails(self):
        result = self.run_check(
            "# no ELIST\nirctest.server_tests.list.ListTestCase::testListMask\n"
            "irctest.server_tests.join.JoinTestCase::testJoin\n"
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("no longer skipped: irctest.server_tests.join", result.stderr)

    def test_an_entry_without_a_reason_fails(self):
        result = self.run_check("irctest.server_tests.list.ListTestCase::testListMask\n")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("has no `#` reason", result.stderr)


if __name__ == "__main__":
    unittest.main()
