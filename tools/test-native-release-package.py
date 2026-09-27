#!/usr/bin/env python3
"""Prove the native packager's members, modes, and reproducibility, and that
the release smoke run rejects a binary that does not run or misreports itself.

The binaries here are stand-ins: text files for the packager, which only copies
them, and POSIX shell scripts for the smoke run, which executes them. The real
binaries are executed by the same smoke script on each target's own runner in
release.yml."""

from __future__ import annotations

import hashlib
import pathlib
import subprocess
import tarfile
import tempfile
import tomllib
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGER = ROOT / "tools/package-native-release.py"
SMOKE = ROOT / "tools/smoke-native-release.py"
REVISION = "0123456789abcdef0123456789abcdef01234567"


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        version = tomllib.load(manifest)["workspace"]["package"]["version"]
    assert isinstance(version, str) and version
    return version


def digest(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def populate(target_directory: pathlib.Path, target: str) -> None:
    suffix = ".exe" if "windows" in target else ""
    for profile, binary in (
        ("release", f"e6ircd{suffix}"),
        ("release-client", f"e6irc{suffix}"),
        ("release-client", f"e6irc-tui{suffix}"),
    ):
        path = target_directory / target / profile / binary
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(f"{target}:{binary}\n".encode())


def package(
    target_directory: pathlib.Path, output_directory: pathlib.Path, target: str
) -> pathlib.Path:
    result = subprocess.run(
        [
            str(PACKAGER),
            "--target",
            target,
            "--target-directory",
            str(target_directory),
            "--output-directory",
            str(output_directory),
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return pathlib.Path(result.stdout.strip())


def rejects_unknown_target(target_directory: pathlib.Path, output_directory: pathlib.Path) -> None:
    result = subprocess.run(
        [
            str(PACKAGER),
            "--target",
            "x86_64-unknown-windows-gnu",
            "--target-directory",
            str(target_directory),
            "--output-directory",
            str(output_directory),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "argument --target" in result.stderr


def expected_names(prefix: str, suffix: str) -> set[str]:
    return {
        f"{prefix}/e6ircd{suffix}",
        f"{prefix}/e6irc{suffix}",
        f"{prefix}/e6irc-tui{suffix}",
        f"{prefix}/README.md",
        f"{prefix}/LICENSE",
        f"{prefix}/deploy/e6ircd.service",
    }


def assert_tar(path: pathlib.Path, prefix: str) -> None:
    with tarfile.open(path, "r:gz") as archive:
        members = {member.name: member for member in archive.getmembers()}
        assert set(members) == expected_names(prefix, "")
        assert members[f"{prefix}/e6ircd"].mode == 0o755
        assert members[f"{prefix}/README.md"].mode == 0o644
        assert all(member.mtime == 0 for member in members.values())


def assert_zip(path: pathlib.Path, prefix: str) -> None:
    with zipfile.ZipFile(path) as archive:
        members = {member.filename: member for member in archive.infolist()}
        assert set(members) == expected_names(prefix, ".exe")
        assert members[f"{prefix}/e6ircd.exe"].external_attr >> 16 & 0o777 == 0o755
        assert members[f"{prefix}/README.md"].external_attr >> 16 & 0o777 == 0o644
        assert all(member.date_time == (1980, 1, 1, 0, 0, 0) for member in members.values())


def populate_executables(
    target_directory: pathlib.Path, target: str, lines: dict[str, str], status: int = 0
) -> None:
    """Shell-script stand-ins that print `lines[binary]` for `--version`."""
    for profile, binary in (
        ("release", "e6ircd"),
        ("release-client", "e6irc"),
        ("release-client", "e6irc-tui"),
    ):
        path = target_directory / target / profile / binary
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            "#!/bin/sh\n"
            '[ "$#" -eq 1 ] && [ "$1" = --version ] || exit 64\n'
            f"printf '%s\\n' '{lines[binary]}'\n"
            f"exit {status}\n"
        )
        path.chmod(0o755)


def run_smoke(target_directory: pathlib.Path, target: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        [
            str(SMOKE),
            "--target",
            target,
            "--target-directory",
            str(target_directory),
            "--revision",
            REVISION,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def smoke_checks(root: pathlib.Path, version: str) -> None:
    target = "x86_64-unknown-linux-gnu"
    honest = {
        "e6ircd": f"e6ircd {version} (revision {REVISION})",
        "e6irc": f"e6irc {version}",
        "e6irc-tui": f"e6irc-tui {version}",
    }
    directory = root / "smoke-honest"
    populate_executables(directory, target, honest)
    result = run_smoke(directory, target)
    assert result.returncode == 0, result.stderr
    for binary, line in honest.items():
        assert f"{binary}: {line}" in result.stdout, (binary, result.stdout)

    for case, lines, status, named in (
        ("a wrong version", {**honest, "e6irc": "e6irc 0.0.0-other"}, 0, "e6irc:"),
        (
            "a daemon built from another revision",
            {**honest, "e6ircd": f"e6ircd {version} (revision unknown)"},
            0,
            "e6ircd:",
        ),
        ("a binary that fails", honest, 3, "exited 3"),
    ):
        directory = root / f"smoke-{case.replace(' ', '-')}"
        populate_executables(directory, target, lines, status)
        result = run_smoke(directory, target)
        assert result.returncode != 0, f"smoke passed {case}"
        assert named in result.stderr, (case, result.stderr)

    missing = root / "smoke-missing"
    populate_executables(missing, target, honest)
    (missing / target / "release-client" / "e6irc-tui").unlink()
    result = run_smoke(missing, target)
    assert result.returncode != 0 and "e6irc-tui: did not run" in result.stderr, result.stderr

    bad_revision = subprocess.run(
        [str(SMOKE), "--target", target, "--revision", "unknown"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    assert bad_revision.returncode != 0 and "--revision" in bad_revision.stderr


def main() -> None:
    version = workspace_version()
    with tempfile.TemporaryDirectory(prefix="e6irc-native-package-") as temporary:
        root = pathlib.Path(temporary)
        target_directory = root / "target"
        rejects_unknown_target(target_directory, root / "invalid")
        for target, assertion in (
            ("x86_64-unknown-linux-gnu", assert_tar),
            ("x86_64-pc-windows-msvc", assert_zip),
        ):
            populate(target_directory, target)
            first = package(target_directory, root / "first", target)
            second = package(target_directory, root / "second", target)
            prefix = f"e6irc-{version}-{target}"
            assertion(first, prefix)
            assert digest(first) == digest(second), f"{target} archive is not reproducible"
        smoke_checks(root, version)
    print("native release package test passed")


if __name__ == "__main__":
    main()
