#!/usr/bin/env python3
"""Execute every native release binary on the runner that built it.

A cross-platform matrix that only compiles proves nothing about whether the
Windows ARM or macOS binary starts: a missing runtime library, a wrong
subsystem or a panic before `main` shows up only when it runs. The release job
runs this on each target's own runner, after the build and before packaging:
each binary the packager would ship (the same list, from
package-native-release.py) must run `--version`, exit 0, and print exactly the
workspace version it was built as, and the daemon also the commit it was built
from. Anything else fails the job, so no archive holds an unexecuted binary.
"""

from __future__ import annotations

import argparse
import importlib.util
import pathlib
import re
import subprocess
import sys


ROOT = pathlib.Path(__file__).resolve().parent.parent
TIMEOUT_SECONDS = 60


def packager():
    spec = importlib.util.spec_from_file_location(
        "package_native_release", ROOT / "tools/package-native-release.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("cannot load tools/package-native-release.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def revision(value: str) -> str:
    if not re.fullmatch(r"[0-9a-f]{40}", value):
        raise argparse.ArgumentTypeError(f"not a full commit hash: {value!r}")
    return value


def expected_line(name: str, version: str, commit: str) -> str:
    stem = name.removesuffix(".exe")
    if stem == "e6ircd":
        return f"e6ircd {version} (revision {commit})"
    return f"{stem} {version}"


def smoke(target: str, target_directory: pathlib.Path, commit: str) -> list[str]:
    """Run each binary; return one problem line per binary that failed."""
    package = packager()
    version = package.workspace_version()
    problems = []
    for name, path in package.executables(package.release_target(target), target_directory):
        try:
            package.validate_source(name, path)
            result = subprocess.run(
                [str(path), "--version"],
                capture_output=True,
                text=True,
                timeout=TIMEOUT_SECONDS,
                stdin=subprocess.DEVNULL,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            problems.append(f"{name}: did not run: {error}")
            continue
        expected = expected_line(name, version, commit)
        if result.returncode != 0:
            problems.append(
                f"{name}: `--version` exited {result.returncode}: {result.stderr.strip()!r}"
            )
        elif result.stdout != expected + "\n":
            problems.append(f"{name}: `--version` printed {result.stdout!r}, not {expected!r}")
        else:
            print(f"{name}: {expected}")
    return problems


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True)
    parser.add_argument("--target-directory", type=pathlib.Path, default=ROOT / "target")
    parser.add_argument("--revision", required=True, type=revision)
    arguments = parser.parse_args()
    try:
        problems = smoke(arguments.target, arguments.target_directory, arguments.revision)
    except ValueError as error:
        sys.exit(f"native release smoke FAILED: {error}")
    if problems:
        print("native release smoke FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
