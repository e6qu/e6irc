#!/usr/bin/env python3
"""Hold an irctest run's skipped tests to a committed list.

irctest skips a test, instead of failing it, when the server does not
advertise what the test needs (`CapabilityNotSupported`,
`OptionalExtensionNotSupported`, ...). A server that stopped advertising a
capability would turn that capability's whole file into skips and the job
would stay green. So every skip must be listed, with the reason above it, and
every listed test must still skip: a new skip fails the run, and so does a
listed test that now runs (it has earned its way off the list).

    check_skips.py <junit.xml> <expected-skips.txt>

The list holds one `classname::name` per line, as the JUnit report names the
test; `#` lines give the reason for the entries below them.
"""

import sys
import xml.etree.ElementTree as ElementTree


def skipped(report: str) -> dict[str, str]:
    """Each skipped test, with the reason irctest gave."""
    tests = {}
    for case in ElementTree.parse(report).getroot().iter("testcase"):
        skip = case.find("skipped")
        if skip is not None:
            tests[f"{case.get('classname')}::{case.get('name')}"] = skip.get("message", "")
    return tests


def expected(listing: str) -> set[str]:
    entries, reason = set(), False
    with open(listing, encoding="utf-8") as lines:
        for number, line in enumerate(lines, 1):
            line = line.strip()
            if not line:
                reason = False
            elif line.startswith("#"):
                reason = True
            elif not reason:
                sys.exit(f"{listing}:{number}: {line} has no `#` reason above it")
            else:
                entries.add(line)
    return entries


def main() -> None:
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    report, listing = sys.argv[1:]
    actual, allowed = skipped(report), expected(listing)
    new, stale = sorted(actual.keys() - allowed), sorted(allowed - actual.keys())
    for test in new:
        print(f"skipped but not in {listing}: {test} ({actual[test]})", file=sys.stderr)
    for test in stale:
        print(f"in {listing} but no longer skipped: {test}", file=sys.stderr)
    if new or stale:
        sys.exit(
            "irctest skips differ from the committed list: fix what made a test "
            "skip, or list it with its reason; drop an entry that now runs"
        )
    print(f"irctest skips: {len(actual)}, each listed with its reason")


if __name__ == "__main__":
    main()
