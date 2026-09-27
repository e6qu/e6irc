#!/usr/bin/env python3
"""Contract test for tools/check-image-pins.py: a repository whose every
pulled image is pinned passes, and each way of pulling one by tag fails."""

from __future__ import annotations

import pathlib
import shutil
import subprocess
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parent.parent
GUARD = ROOT / "tools/check-image-pins.py"
A = "@sha256:" + "a" * 64
B = "@sha256:" + "b" * 64

CLEAN = {
    "Dockerfile": f"""# syntax=docker/dockerfile:1
FROM node:24{A} AS web
RUN true
FROM --platform=$BUILDPLATFORM rust:1.98.1{A} AS build
COPY --from=web /src /src
FROM gcr.io/distroless/cc:nonroot{A}
COPY --from=build /out /out
""",
    "vendor/oracle/Dockerfile": f"FROM debian:bullseye-slim{A}\n",
    ".github/workflows/ci.yml": f"""jobs:
  test:
    services:
      postgres:
        image: postgres:18{A}
    container: node:24{A}
    steps:
      - run: docker build --tag local:ci .
      - run: docker run --rm local:ci --version
      - run: |
          docker run -d --name dex -p 1:2 \\
            -v "$PWD/x:/y" \\
            ghcr.io/dexidp/dex:v2{A} dex serve
          id="$(docker create local:ci)"
          docker run --rm "$image" --version
      - uses: anchore/sbom-action@0000000000000000000000000000000000000000
        with:
          image: ${{{{ env.IMAGE }}}}:tag
""",
    "oracle/docker-compose.yml": f"services:\n  conduit:\n    image: conduit:v0.9{A}\n",
    "tools/run.sh": f"""#!/usr/bin/env bash
image="${{IMAGE:-postgres:18{A}}}"
docker run --detach --network net --env A=b "$image" >/dev/null
""",
    "tools/recovery.py": f'IMAGE = "postgres:18{A}"\n',
    # Documentation may name an image by tag.
    "README.md": "Run `docker run postgres:18` to try it.\n",
}

BROKEN = {
    "an unpinned FROM": ("Dockerfile", f"FROM node:24{A} AS web", "FROM node:24 AS web"),
    "an unpinned FROM with --platform": (
        "Dockerfile",
        f"FROM --platform=$BUILDPLATFORM rust:1.98.1{A} AS build",
        "FROM --platform=$BUILDPLATFORM rust:1.98.1 AS build",
    ),
    "an unpinned final stage": ("Dockerfile", f"FROM gcr.io/distroless/cc:nonroot{A}", "FROM gcr.io/distroless/cc:nonroot"),
    "COPY --from an unpinned image": ("Dockerfile", "COPY --from=web /src /src", "COPY --from=alpine:3 /src /src"),
    "an unpinned vendored Dockerfile": ("vendor/oracle/Dockerfile", f"FROM debian:bullseye-slim{A}", "FROM debian:bullseye-slim"),
    "an unpinned service image": (".github/workflows/ci.yml", f"image: postgres:18{A}", "image: postgres:18"),
    "an unpinned job container": (".github/workflows/ci.yml", f"container: node:24{A}", "container: node:24"),
    "an unpinned continued docker run": (
        ".github/workflows/ci.yml",
        f"ghcr.io/dexidp/dex:v2{A} dex serve",
        "ghcr.io/dexidp/dex:v2 dex serve",
    ),
    "an unpinned docker create": (".github/workflows/ci.yml", "docker create local:ci", "docker create alpine:3"),
    "an unpinned docker pull": (".github/workflows/ci.yml", "docker build --tag local:ci .", "docker pull alpine:3"),
    "an unpinned compose image": ("oracle/docker-compose.yml", f"image: conduit:v0.9{A}", "image: conduit:v0.9"),
    "an unpinned docker run in a script": (
        "tools/run.sh",
        '"$image" >/dev/null',
        "alpine:3 >/dev/null",
    ),
    "a tag-only default of a pinned image": ("tools/run.sh", f"postgres:18{A}", "postgres:18"),
    "a tag-only constant of a pinned image": ("tools/recovery.py", f"postgres:18{A}", "postgres:18"),
    "a second digest for one image": ("tools/recovery.py", f"postgres:18{A}", f"postgres:18{B}"),
}


def git(repo: pathlib.Path, *arguments: str) -> None:
    subprocess.run(["git", *arguments], cwd=repo, check=True, capture_output=True)


def build(repo: pathlib.Path, files: dict[str, str]) -> None:
    if repo.exists():
        shutil.rmtree(repo)
    repo.mkdir(parents=True)
    git(repo, "init", "-q")
    for name, text in files.items():
        path = repo / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")


def guard(repo: pathlib.Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(GUARD), str(repo)], capture_output=True, text=True
    )


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="e6irc-image-pins-") as temporary:
        repo = pathlib.Path(temporary) / "repo"
        build(repo, CLEAN)
        clean = guard(repo)
        assert clean.returncode == 0, clean.stderr
        assert "clean (7 images" in clean.stdout, clean.stdout

        for case, (name, old, new) in BROKEN.items():
            files = dict(CLEAN)
            text = files[name]
            assert old in text, (case, old)
            files[name] = text.replace(old, new, 1)
            build(repo, files)
            result = guard(repo)
            assert result.returncode != 0, f"guard passed {case}"
            assert "image-pin guard FAILED" in result.stderr, (case, result.stderr)

        build(repo, {"README.md": "nothing to pull\n"})
        empty = guard(repo)
        assert empty.returncode != 0 and "checked nothing" in empty.stderr, empty.stderr
    print("image-pin guard contract ok")


if __name__ == "__main__":
    main()
