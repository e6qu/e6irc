#!/usr/bin/env python3
"""Every service and tool image is pinned by one digest, everywhere it runs.

ci.yml's header names the images CI runs besides its own ("Service and tool
images are pinned by digest"). A tag can be moved to other code; a digest
cannot. So each non-comment reference to one of those images, in any tracked
file other than documentation, must carry `@sha256:`, and every reference to
one image must carry the same digest: a script that runs `postgres:18-alpine`
bare, or pins a different digest than CI, tests against an image CI never
qualified.
"""

import re
import subprocess
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def pinned_images(root: Path) -> list[str]:
    """The `NAME:TAG` list in ci.yml's image-pinning comment."""
    text = (root / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    block = re.search(r"# Service and tool images are pinned by digest.*?\n((?:#.*\n)+)", text)
    if not block:
        sys.exit("image-pin guard: ci.yml no longer has its image-pinning comment")
    images = re.findall(r"([a-z0-9./-]+:[A-Za-z0-9._-]+)", block.group(1))
    if not images:
        sys.exit("image-pin guard: ci.yml's image-pinning comment names no image")
    return images


def tracked_files(root: Path) -> list[Path]:
    names = subprocess.run(
        ["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True
    ).stdout.split(b"\0")
    return [root / name.decode() for name in names if name and not name.endswith(b".md")]


def check(root: Path, images: list[str]) -> list[str]:
    problems = []
    digests: dict[str, dict[str, list[str]]] = defaultdict(lambda: defaultdict(list))
    pattern = re.compile(
        "(" + "|".join(re.escape(image) for image in images) + r")(@sha256:[0-9a-f]{64})?(?![\w.-])"
    )
    for path in tracked_files(root):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
        for number, line in enumerate(lines, 1):
            if line.lstrip().startswith("#"):
                continue
            for match in pattern.finditer(line):
                where = f"{path.relative_to(root)}:{number}"
                if match.group(2) is None:
                    problems.append(f"{where}: {match.group(1)} is not pinned by digest")
                else:
                    digests[match.group(1)][match.group(2)].append(where)
    for image, by_digest in digests.items():
        if len(by_digest) > 1:
            places = "; ".join(
                f"{digest[8:20]}… at {', '.join(where)}" for digest, where in by_digest.items()
            )
            problems.append(f"{image} is pinned to {len(by_digest)} digests: {places}")
    return problems


def main() -> None:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else ROOT
    images = pinned_images(root)
    problems = check(root, images)
    if problems:
        print("image-pin guard FAILED:", file=sys.stderr)
        for problem in problems:
            print(f"  {problem}", file=sys.stderr)
        sys.exit(1)
    print(f"image-pin guard: clean ({len(images)} images, one digest each)")


if __name__ == "__main__":
    main()
