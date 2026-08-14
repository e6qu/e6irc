#!/usr/bin/env python3
"""Build a deterministic native release archive from already-built binaries."""

from __future__ import annotations

import argparse
import gzip
import io
import pathlib
import stat
import tarfile
import tomllib
import zipfile


ROOT = pathlib.Path(__file__).resolve().parent.parent
RELEASE_TARGETS = frozenset(
    {
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "x86_64-apple-darwin",
        "aarch64-apple-darwin",
        "x86_64-pc-windows-msvc",
        "aarch64-pc-windows-msvc",
    }
)
DOCUMENTS = (
    ("README.md", ROOT / "README.md"),
    ("LICENSE", ROOT / "LICENSE"),
    ("deploy/e6ircd.service", ROOT / "deploy/e6ircd.service"),
)


def workspace_version() -> str:
    with (ROOT / "Cargo.toml").open("rb") as manifest:
        value = tomllib.load(manifest)["workspace"]["package"]["version"]
    if not isinstance(value, str) or not value:
        raise ValueError("workspace.package.version must be a non-empty string")
    return value


def release_target(value: str) -> str:
    if value not in RELEASE_TARGETS:
        raise ValueError(f"unsupported release target: {value}")
    return value


def source_files(
    target: str, target_directory: pathlib.Path
) -> tuple[tuple[str, pathlib.Path, int], ...]:
    suffix = ".exe" if "windows" in target else ""
    return (
        (
            f"e6ircd{suffix}",
            target_directory / target / "release" / f"e6ircd{suffix}",
            0o755,
        ),
        (
            f"e6irc{suffix}",
            target_directory / target / "release-client" / f"e6irc{suffix}",
            0o755,
        ),
        (
            f"e6irc-tui{suffix}",
            target_directory / target / "release-client" / f"e6irc-tui{suffix}",
            0o755,
        ),
        *((name, path, 0o644) for name, path in DOCUMENTS),
    )


def validate_source(name: str, path: pathlib.Path) -> None:
    if path.is_symlink() or not path.is_file():
        raise FileNotFoundError(f"release member {name} is not a regular file: {path}")


def write_tar_gz(
    output: pathlib.Path,
    prefix: str,
    members: tuple[tuple[str, pathlib.Path, int], ...],
) -> None:
    with output.open("wb") as raw:
        with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0) as compressed:
            with tarfile.open(mode="w", fileobj=compressed, format=tarfile.PAX_FORMAT) as archive:
                for name, path, mode in members:
                    data = path.read_bytes()
                    info = tarfile.TarInfo(f"{prefix}/{name}")
                    info.size = len(data)
                    info.mode = mode
                    info.mtime = 0
                    info.uid = 0
                    info.gid = 0
                    info.uname = ""
                    info.gname = ""
                    archive.addfile(info, fileobj=io.BytesIO(data))


def write_zip(
    output: pathlib.Path,
    prefix: str,
    members: tuple[tuple[str, pathlib.Path, int], ...],
) -> None:
    with zipfile.ZipFile(
        output, mode="w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for name, path, mode in members:
            info = zipfile.ZipInfo(f"{prefix}/{name}", date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = (stat.S_IFREG | mode) << 16
            archive.writestr(info, path.read_bytes(), compresslevel=9)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, type=release_target)
    parser.add_argument("--target-directory", type=pathlib.Path, default=ROOT / "target")
    parser.add_argument("--output-directory", type=pathlib.Path, default=ROOT / "dist")
    arguments = parser.parse_args()

    version = workspace_version()
    prefix = f"e6irc-{version}-{arguments.target}"
    members = source_files(arguments.target, arguments.target_directory)
    for name, path, _mode in members:
        validate_source(name, path)

    arguments.output_directory.mkdir(parents=True, exist_ok=True)
    extension = ".zip" if "windows" in arguments.target else ".tar.gz"
    output = arguments.output_directory / f"{prefix}{extension}"
    if extension == ".zip":
        write_zip(output, prefix, members)
    else:
        write_tar_gz(output, prefix, members)
    print(output)


if __name__ == "__main__":
    main()
