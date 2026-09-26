#!/usr/bin/env python3
"""Validate that every shipped user journey is complete and traceable."""

from __future__ import annotations

import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
JOURNEY_DIRECTORY = ROOT / "docs" / "journeys"
REQUIRED_BLOCKS = (
    "Actor and goal",
    "Preconditions",
    "Flow",
    "Visible failures and recovery",
    "Security and observability",
    "Evidence",
)
EVIDENCE_STATES = {
    "Proven",
    "Partially proven",
    "Externally qualified",
    "Unproven",
}
BLOCK_PATTERN = re.compile(r"^\*\*([^*]+)\.\*\*(.*)$", re.MULTILINE)
HEADING_PATTERN = re.compile(r"^## ([^#].+)$", re.MULTILINE)
COVERAGE_ROW_PATTERN = re.compile(
    r"^\| \[([^\]]+)\]\(([^)#]+)#([^)]+)\) \| ([^|]+) \|",
    re.MULTILINE,
)
CODE_SPAN_PATTERN = re.compile(r"`([^`]+)`")
# What an Evidence block cites by name. A snake_case identifier is a test
# function; a relative path is a file in this repository. Routes (`/ws/ui`),
# commands (`e6irc login`) and protocol words (`ERROR`) fit neither shape.
TEST_NAME_PATTERN = re.compile(r"[a-z][a-z0-9]*(?:_[a-z0-9]+)+")
REPOSITORY_PATH_PATTERN = re.compile(r"[\w.-]+(?:/[\w.-]+)+")
RUST_TEST_ROOTS = ("crates", "fuzz")
SCRIPTED_TEST_ROOTS = ("web/test", "tools")


def github_anchor(heading: str) -> str:
    """Return the GitHub-style anchor used by the journey links."""

    anchor = heading.strip().lower()
    anchor = re.sub(r"[^\w\-\s]", "", anchor, flags=re.UNICODE)
    anchor = re.sub(r"\s+", "-", anchor)
    return anchor


def fail(errors: list[str], message: str) -> None:
    errors.append(message)


# A Rust test: a function whose attributes include `#[test]` or an async
# runtime's `#[tokio::test(..)]`.
RUST_TEST = re.compile(
    r"((?:#\[[^\]]*\]\s*)+)(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([a-z_][a-z0-9_]*)"
)
RUST_TEST_ATTRIBUTE = re.compile(r"#\[\s*(?:tokio::)?test\b")
# A scripted test: a `test("title", ..)` / `it("title", ..)` case (node:test,
# Playwright, or the tool suites' own `test` helper), or a Python `test_` case.
SCRIPTED_TEST = re.compile(
    r"\b(?:test|it)(?:\.\w+)?\(\s*[\"'`]([a-z][a-z0-9_]*)[\"'`]|\bdef\s+(test_[a-z0-9_]*)"
)


def defined_test_names() -> set[str]:
    """Every name an Evidence block may cite as a test: a Rust test function,
    or a scripted suite's test case. A production function of the same shape
    is not evidence of anything, so it is not a test name.
    """

    names: set[str] = set()
    for root in RUST_TEST_ROOTS:
        for path in (ROOT / root).rglob("*.rs"):
            if "target" in path.relative_to(ROOT).parts:
                continue
            for attributes, name in RUST_TEST.findall(path.read_text(encoding="utf-8")):
                if RUST_TEST_ATTRIBUTE.search(attributes):
                    names.add(name)
    for root in SCRIPTED_TEST_ROOTS:
        for path in (ROOT / root).rglob("*"):
            if path.suffix not in {".js", ".mjs", ".py", ".sh"} or not path.is_file():
                continue
            if "node_modules" in path.relative_to(ROOT).parts:
                continue
            for title, function in SCRIPTED_TEST.findall(path.read_text(encoding="utf-8")):
                names.add(title or function)
    return names


def check_ci_aggregate(errors: list[str], jobs_section: str, jobs: set[str]) -> None:
    """`ci-ok` is the required check, so it must need every other job.

    A job left out of its `needs` could fail without failing the one check
    branch protection looks at.
    """

    aggregate = re.search(
        r"^  ci-ok:\n(?:    .*\n|\n)*?    needs:\s*\[(?P<needs>[^\]]*)\]",
        jobs_section,
        re.MULTILINE,
    )
    if aggregate is None:
        fail(errors, "ci.yml has no `ci-ok` job with an inline `needs: [...]` list")
        return
    needed = set(re.findall(r"[a-z][a-z0-9-]*", aggregate.group("needs")))
    for job in sorted(jobs - needed - {"ci-ok"}):
        fail(errors, f"ci.yml `ci-ok` does not need the job `{job}`")
    for job in sorted(needed - jobs):
        fail(errors, f"ci.yml `ci-ok` needs `{job}`, which is not a job")
    if "if: always()" not in jobs_section[aggregate.start() : aggregate.end()]:
        fail(errors, "ci.yml `ci-ok` must run with `if: always()`")


def check_ci_mapping(errors: list[str], coverage: str) -> None:
    """The CI mapping names every job the workflow runs, and no job it does not."""

    workflow = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    jobs_section = workflow.split("\njobs:\n", 1)
    if len(jobs_section) != 2:
        fail(errors, "ci.yml has no jobs section to compare the CI mapping against")
        return
    jobs = set(re.findall(r"^  ([a-z][a-z0-9-]*):$", jobs_section[1], re.MULTILINE))
    check_ci_aggregate(errors, jobs_section[1], jobs)
    mapping = coverage.split("## CI mapping", 1)
    if len(mapping) != 2:
        fail(errors, "coverage.md has no CI mapping section")
        return
    mapped: set[str] = set()
    for row in re.findall(r"^\| (`[^|]+) \|", mapping[1], re.MULTILINE):
        mapped.update(CODE_SPAN_PATTERN.findall(row))
    for job in sorted(jobs - mapped):
        fail(errors, f"coverage.md CI mapping omits the CI job `{job}`")
    for job in sorted(mapped - jobs):
        fail(errors, f"coverage.md CI mapping names `{job}`, which is not a CI job")


def check_evidence_citations(
    errors: list[str], journey: str, evidence: str, test_names: set[str]
) -> None:
    """Resolve what an Evidence block names, so a removed test cannot stay cited."""

    for citation in CODE_SPAN_PATTERN.findall(re.sub(r"\s*\n\s*", " ", evidence)):
        if TEST_NAME_PATTERN.fullmatch(citation):
            if citation not in test_names:
                fail(errors, f"{journey} cites the test `{citation}`, which does not exist")
        elif REPOSITORY_PATH_PATTERN.fullmatch(citation):
            if not (ROOT / citation).exists():
                fail(errors, f"{journey} cites the path `{citation}`, which does not exist")


def main() -> int:
    errors: list[str] = []
    journey_files = sorted(
        path
        for path in JOURNEY_DIRECTORY.glob("*.md")
        if path.name not in {"README.md", "coverage.md"}
    )
    if not journey_files:
        fail(errors, "no journey documents found")

    readme = (JOURNEY_DIRECTORY / "README.md").read_text(encoding="utf-8")
    coverage = (JOURNEY_DIRECTORY / "coverage.md").read_text(encoding="utf-8")
    coverage_rows: dict[tuple[str, str], tuple[str, str]] = {}
    for label, filename, anchor, state in COVERAGE_ROW_PATTERN.findall(coverage):
        key = (filename, anchor)
        if key in coverage_rows:
            fail(errors, f"coverage.md has duplicate row for {filename}#{anchor}")
        coverage_rows[key] = (label, state.strip())

    check_ci_mapping(errors, coverage)

    expected: dict[tuple[str, str], str] = {}
    test_names = defined_test_names()
    for path in journey_files:
        relative_name = path.name
        if f"({relative_name})" not in readme:
            fail(errors, f"README.md catalog does not link {relative_name}")

        text = path.read_text(encoding="utf-8")
        headings = list(HEADING_PATTERN.finditer(text))
        if not headings:
            fail(errors, f"{relative_name} has no journeys")
            continue

        for index, heading_match in enumerate(headings):
            title = heading_match.group(1).strip()
            anchor = github_anchor(title)
            key = (relative_name, anchor)
            if key in expected:
                fail(errors, f"duplicate journey anchor {relative_name}#{anchor}")
            expected[key] = title

            end = headings[index + 1].start() if index + 1 < len(headings) else len(text)
            section = text[heading_match.end() : end]
            blocks = {
                match.group(1).strip(): match
                for match in BLOCK_PATTERN.finditer(section)
            }
            for required in REQUIRED_BLOCKS:
                match = blocks.get(required)
                if match is None:
                    fail(
                        errors,
                        f"{relative_name}#{anchor} is missing **{required}.**",
                    )
                    continue
                block_end = min(
                    (
                        other.start()
                        for other in BLOCK_PATTERN.finditer(section)
                        if other.start() > match.start()
                    ),
                    default=len(section),
                )
                content = f"{match.group(2)}\n{section[match.end() : block_end]}".strip()
                if len(content) < 20:
                    fail(
                        errors,
                        f"{relative_name}#{anchor} has an empty or cursory "
                        f"**{required}.** block",
                    )
                if required == "Evidence":
                    check_evidence_citations(
                        errors, f"{relative_name}#{anchor}", content, test_names
                    )

    for key, title in expected.items():
        row = coverage_rows.get(key)
        if row is None:
            fail(errors, f"coverage.md has no row for {key[0]}#{key[1]} ({title})")
            continue
        label, state = row
        if label != title:
            fail(
                errors,
                f"coverage.md labels {key[0]}#{key[1]} as {label!r}, expected {title!r}",
            )
        if state not in EVIDENCE_STATES:
            fail(
                errors,
                f"coverage.md uses undefined evidence state {state!r} for {title}",
            )

    for key in coverage_rows.keys() - expected.keys():
        fail(errors, f"coverage.md links unknown journey {key[0]}#{key[1]}")

    if errors:
        for error in errors:
            print(f"journey guard: {error}", file=sys.stderr)
        print(
            f"journey guard FAILED ({len(errors)} problem"
            f"{'s' if len(errors) != 1 else ''})",
            file=sys.stderr,
        )
        return 1

    print(
        f"journey guard: clean ({len(expected)} journeys across "
        f"{len(journey_files)} documents)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
