#!/usr/bin/env python3
"""Every container image this repository pulls is pinned by digest, one each.

A tag can be moved to other code; a digest cannot. In every tracked file other
than documentation (`*.md`), each image reference must carry `@sha256:`:

  - `FROM IMAGE` (and `COPY --from=IMAGE`) in a Dockerfile or Containerfile,
    other than an earlier build stage;
  - `image: IMAGE` and `container: IMAGE` in a workflow or compose file (a job
    container, a service container, a compose service);
  - the image operand of `docker run` / `docker create` / `docker pull`, in a
    shell script or a workflow's `run:` step.

An operand that is a variable or an expression (`"$image"`, `${{ … }}`) is the
caller's image, and an image built in the same file (`docker build --tag
NAME`) is local; neither is pulled, so neither is a reference here. Every
other mention of an image found above, anywhere else (a Python constant, a
script's default value), must carry the digest too, and every reference to one
`NAME:TAG` must carry the same digest: a script that runs a pinned image by its
tag alone, or by another digest than CI, runs an image CI never qualified.
"""

from __future__ import annotations

import re
import shlex
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

DIGEST = r"@sha256:[0-9a-f]{64}"
# NAME[:TAG][@sha256:…] — a registry path, then an optional tag and digest.
IMAGE = re.compile(r"^(?P<name>[a-z0-9][a-z0-9._/-]*(?::[0-9]+/[a-z0-9._/-]+)?)(?::(?P<tag>[A-Za-z0-9._-]+))?(?P<digest>" + DIGEST + ")?$")
# `docker run`/`create` options that take no value; any other option not
# written `--name=value` consumes the next word.
FLAGS = frozenset(
    "-d --detach --rm -i --interactive -t --tty -it -ti --init --privileged "
    "--read-only -q --quiet --all-tags -a --disable-content-trust".split()
)


# This guard's contract test writes unpinned references on purpose.
EXEMPT = frozenset({b"tools/test-check-image-pins.py"})


def tracked_files(root: Path) -> list[Path]:
    names = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
    ).stdout.split(b"\0")
    return [
        root / name.decode()
        for name in names
        if name and not name.endswith(b".md") and name not in EXEMPT
    ]


def is_dockerfile(path: Path) -> bool:
    name = path.name
    return (
        name in ("Dockerfile", "Containerfile")
        or name.startswith(("Dockerfile.", "Containerfile."))
        or name.endswith((".Dockerfile", ".dockerfile", ".Containerfile"))
    )


def is_yaml(path: Path) -> bool:
    return path.suffix in (".yml", ".yaml")


def is_shell(path: Path) -> bool:
    return path.suffix in (".sh", ".bash")


def logical_lines(lines: list[str]) -> list[tuple[int, str]]:
    """Join backslash-continued lines, keeping the first line's number."""
    joined: list[tuple[int, str]] = []
    pending: tuple[int, str] | None = None
    for number, line in enumerate(lines, 1):
        stripped = line.rstrip()
        if pending is not None:
            start, text = pending
            text = text + " " + stripped.lstrip()
        else:
            start, text = number, stripped
        if text.endswith("\\"):
            pending = (start, text[:-1])
        else:
            pending = None
            joined.append((start, text))
    if pending is not None:
        joined.append(pending)
    return joined


def dynamic(word: str) -> bool:
    return "$" in word or "{{" in word


def references(path: Path, text: str) -> list[tuple[int, str]]:
    """(line, image) for each image operand this file pulls."""
    found: list[tuple[int, str]] = []
    lines = text.splitlines()
    if is_dockerfile(path):
        stages: set[str] = set()
        for number, line in logical_lines(lines):
            words = line.split()
            if not words or words[0].startswith("#"):
                continue
            keyword = words[0].upper()
            if keyword == "FROM":
                operands = [word for word in words[1:] if not word.startswith("--")]
                if not operands:
                    continue
                image = operands[0]
                if len(operands) >= 3 and operands[1].upper() == "AS":
                    stages.add(operands[2].lower())
                if image.lower() not in stages and image != "scratch" and not dynamic(image):
                    found.append((number, image))
            elif keyword in ("COPY", "ADD"):
                for word in words[1:]:
                    if word.startswith("--from="):
                        source = word.split("=", 1)[1]
                        if source.lower() not in stages and not source.isdigit() and not dynamic(source):
                            found.append((number, source))
    local: set[str] = set()
    if is_yaml(path) or is_shell(path):
        commands = logical_lines(lines)
        for _number, line in commands:
            for match in re.finditer(r"docker(?:\s+buildx)?\s+build\s[^\n]*?(?:--tag|-t)[ =](\S+)", line):
                local.add(match.group(1).strip("'\""))
        for number, line in commands:
            code = line.split(" #", 1)[0] if not line.lstrip().startswith("#") else ""
            if is_yaml(path):
                key = re.match(r"^\s*-?\s*(image|container):\s*(\S+)\s*$", code)
                if key and not dynamic(key.group(2)) and key.group(2) not in local:
                    found.append((number, key.group(2).strip("'\"")))
            for match in re.finditer(r"docker\s+(run|create|pull)\s+(.*)", code):
                # The command ends at a shell operator or the end of a `$(…)`.
                command = re.split(r"[);|&`]", match.group(2), maxsplit=1)[0]
                try:
                    words = shlex.split(command, comments=True)
                except ValueError:
                    words = command.split()
                operand = None
                skip = False
                for word in words:
                    if skip:
                        skip = False
                        continue
                    if word.startswith("-"):
                        skip = "=" not in word and word not in FLAGS
                        continue
                    operand = word
                    break
                if operand is None:
                    found.append((number, "<docker " + match.group(1) + " without an image>"))
                elif not dynamic(operand) and operand not in local:
                    found.append((number, operand))
    return found


def check(root: Path) -> tuple[list[str], int]:
    problems: list[str] = []
    texts: dict[Path, str] = {}
    for path in tracked_files(root):
        try:
            texts[path] = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue

    named: set[str] = set()
    for path, text in texts.items():
        for number, image in references(path, text):
            where = f"{path.relative_to(root)}:{number}"
            parsed = IMAGE.match(image)
            if parsed is None:
                problems.append(f"{where}: {image!r} is not an image reference this guard can read")
                continue
            if parsed.group("digest") is None:
                problems.append(f"{where}: {image} is not pinned by digest")
            named.add(parsed.group("name") + (f":{parsed.group('tag')}" if parsed.group("tag") else ""))

    # Every mention of a referenced NAME:TAG, in any file: pinned, and to one digest.
    digests: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    tagged = sorted(image for image in named if ":" in image.rsplit("/", 1)[-1])
    if tagged:
        pattern = re.compile(
            # Not the tail of a longer name (`my-postgres:18`), but a shell
            # default (`${IMAGE:-postgres:18}`) is a mention.
            r"(?:(?<![\w./-])|(?<=:-))(" + "|".join(re.escape(image) for image in tagged) + r")(" + DIGEST + r")?(?![\w.-])"
        )
        for path, text in texts.items():
            for number, line in enumerate(text.splitlines(), 1):
                if line.lstrip().startswith("#"):
                    continue
                for match in pattern.finditer(line):
                    where = f"{path.relative_to(root)}:{number}"
                    if match.group(2) is None:
                        problem = f"{where}: {match.group(1)} is not pinned by digest"
                        if problem not in problems:
                            problems.append(problem)
                    else:
                        digests[match.group(1)][match.group(2)].append(where)
    for image, by_digest in sorted(digests.items()):
        if len(by_digest) > 1:
            places = "; ".join(
                f"{digest[8:20]}… at {', '.join(where)}" for digest, where in by_digest.items()
            )
            problems.append(f"{image} is pinned to {len(by_digest)} digests: {places}")
    return problems, len(named)


def main() -> None:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT
    problems, count = check(root)
    if problems:
        print("image-pin guard FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        sys.exit(1)
    if count == 0:
        sys.exit("image-pin guard: found no image reference at all, so it checked nothing")
    print(f"image-pin guard: clean ({count} images, each pinned by one digest)")


if __name__ == "__main__":
    main()
