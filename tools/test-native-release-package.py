#!/usr/bin/env python3
"""Prove the native packager's members, modes, and reproducibility."""

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


def main() -> None:
    version = workspace_version()
    with tempfile.TemporaryDirectory(prefix="e6irc-native-package-") as temporary:
        root = pathlib.Path(temporary)
        target_directory = root / "target"
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
    print("native release package test passed")


if __name__ == "__main__":
    main()
