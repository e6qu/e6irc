#!/usr/bin/env python3
"""Every pinned image is current with Docker Hub, past a 24-hour quarantine.

tools/check-image-pins.py makes every pulled image a Docker Hub copy pinned by
tag and digest: public.ecr.aws/docker/library/NAME for Docker's official
images, mirror.gcr.io/REPOSITORY for the rest. A digest that never moves rots,
so this check compares each pin with Docker Hub, reading Docker Hub's tag API
and the mirror's manifest:

  ok     the pin is the digest Docker Hub serves for its tag, and the mirror
         serves that digest too;
  HELD   Docker Hub moved the tag, or published a newer release with the same
         variant and major version (`1.98.2-bookworm` after
         `1.98.1-bookworm`), less than 24 hours ago;
  DRIFT  that newer digest or release is at least 24 hours old, or the mirror
         serves another digest for the tag than the pin. Fails.

It makes three or four requests per image and spaces its ECR Public requests
1.1 seconds apart: ECR Public allows one unauthenticated request per second.
Unlike the other guards it needs the network, so it is not a tools/gate.sh
step; the `image-freshness` workflow runs it on every pull request, every push
to main, and daily.
"""

from __future__ import annotations

import datetime as dt
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
WAIT = dt.timedelta(hours=24)
PIN = re.compile(
    r"(public\.ecr\.aws/docker/library|mirror\.gcr\.io)/([a-z0-9._/-]+):([A-Za-z0-9._-]+)@(sha256:[0-9a-f]{64})"
)
VERSION = re.compile(r"(v?)(\d+(?:\.\d+)*)(-[A-Za-z0-9._-]+)?")
MANIFEST_TYPES = ", ".join(
    [
        "application/vnd.oci.image.index.v1+json",
        "application/vnd.docker.distribution.manifest.list.v2+json",
        "application/vnd.oci.image.manifest.v1+json",
        "application/vnd.docker.distribution.manifest.v2+json",
    ]
)
ECR_SPACING = 1.1

# Not scanned: the guards' contract tests, whose pins are fixtures that are
# never pulled (an invented digest, a `rust:1.0.0` the release-toolchain test
# must refuse).
EXCLUDED = ("tools/test-check-",)


def timestamp(value: str) -> dt.datetime:
    return dt.datetime.fromisoformat(value.replace("Z", "+00:00"))


def pins(files: list[tuple[str, str]]) -> dict[tuple[str, str, str, str, str], set[str]]:
    """(registry, path, Docker Hub repository, tag, digest) -> files pinning it."""
    found: dict[tuple[str, str, str, str, str], set[str]] = {}
    for name, text in files:
        for registry, path, tag, digest in PIN.findall(text):
            hub = path if registry == "mirror.gcr.io" and "/" in path else "library/" + path
            found.setdefault((registry, path, hub, tag, digest), set()).add(name)
    return found


def newer_releases(tag: str, candidates: list[tuple[str, dt.datetime]]) -> list[tuple[str, dt.datetime]]:
    """The candidate tags that are newer releases of `tag`'s major version with
    the same variant, newest first. A tag that is not a version (`alpine`,
    `buildx-stable-1`) has none."""
    match = VERSION.fullmatch(tag)
    if not match:
        return []
    prefix, numbers, variant = match[1], tuple(map(int, match[2].split("."))), match[3] or ""
    newer = []
    for name, pushed in candidates:
        other = VERSION.fullmatch(name)
        if not other or other[1] != prefix or (other[3] or "") != variant:
            continue
        version = tuple(map(int, other[2].split(".")))
        if len(version) == len(numbers) and version[0] == numbers[0] and version > numbers:
            newer.append((version, name, pushed))
    return [(name, pushed) for _, name, pushed in sorted(newer, reverse=True)]


def verdict(
    pinned: str,
    hub_digest: str,
    hub_pushed: dt.datetime,
    mirror_digest: str,
    newer: list[tuple[str, dt.datetime]],
    now: dt.datetime,
) -> tuple[str, list[str]]:
    drift: list[str] = []
    held: list[str] = []
    if hub_digest != pinned:
        note = f"Docker Hub has served {hub_digest} for the tag since {hub_pushed.isoformat()}"
        (drift if now - hub_pushed >= WAIT else held).append(note)
    elif mirror_digest != pinned:
        drift.append(f"the mirror serves {mirror_digest} for the tag, not the pinned digest")
    eligible = [(name, pushed) for name, pushed in newer if now - pushed >= WAIT]
    if eligible:
        drift.append(f"newer release {eligible[0][0]} has been on Docker Hub since {eligible[0][1].isoformat()}")
    elif newer:
        held.append(f"newer release {newer[0][0]} is inside the 24-hour quarantine")
    if drift:
        return "DRIFT", drift
    if held:
        return "HELD", held
    return "ok", []


# A registry that answers 429 says when to come back (Retry-After); the shared
# runners' addresses are also used by other jobs, so honour it a few times and
# say so, then give up loudly.
ATTEMPTS = 3
_last_ecr = 0.0


def request(url: str, headers: dict[str, str] | None = None, method: str = "GET"):
    global _last_ecr
    ecr = url.startswith("https://public.ecr.aws/")
    for attempt in range(1, ATTEMPTS + 1):
        if ecr:
            time.sleep(max(0.0, _last_ecr + ECR_SPACING - time.monotonic()))
        req = urllib.request.Request(url, method=method, headers={"User-Agent": "e6irc-image-freshness", **(headers or {})})
        try:
            with urllib.request.urlopen(req, timeout=20) as response:
                return response.headers, response.read()
        except urllib.error.HTTPError as error:
            if error.code != 429 or attempt == ATTEMPTS:
                raise OSError(f"{method} {url}: HTTP {error.code}") from error
            after = error.headers.get("Retry-After", "")
            wait = int(after) if after.isdigit() else 5 * attempt
            print(f"note: {method} {url} answered 429; retrying in {wait}s", file=sys.stderr)
            time.sleep(wait)
        finally:
            if ecr:
                _last_ecr = time.monotonic()
    raise AssertionError("unreachable")


def mirror_digest(registry: str, path: str, tag: str) -> str:
    headers = {"Accept": MANIFEST_TYPES}
    if registry == "mirror.gcr.io":
        reply, _ = request(f"https://mirror.gcr.io/v2/{path}/manifests/{tag}", headers, "HEAD")
    else:
        scope = urllib.parse.quote(f"repository:docker/library/{path}:pull", safe="")
        _, body = request(f"https://public.ecr.aws/token/?scope={scope}&service=public.ecr.aws")
        headers["Authorization"] = "Bearer " + json.loads(body)["token"]
        reply, _ = request(f"https://public.ecr.aws/v2/docker/library/{path}/manifests/{tag}", headers, "HEAD")
    digest = reply["Docker-Content-Digest"]
    if not digest:
        raise ValueError(f"{registry} returned no digest for {path}:{tag}")
    return digest


def hub_tag(hub: str, tag: str) -> tuple[str, dt.datetime]:
    _, body = request(f"https://hub.docker.com/v2/repositories/{hub}/tags/{urllib.parse.quote(tag, safe='')}")
    data = json.loads(body)
    return data["digest"], timestamp(data["tag_last_pushed"])


def hub_releases(hub: str, tag: str) -> list[tuple[str, dt.datetime]]:
    match = VERSION.fullmatch(tag)
    if not match:
        return []
    major = urllib.parse.quote(match[1] + match[2].split(".")[0] + ".", safe="")
    _, body = request(
        f"https://hub.docker.com/v2/repositories/{hub}/tags?page_size=100&ordering=last_updated&name={major}"
    )
    return [
        (row["name"], timestamp(row["tag_last_pushed"]))
        for row in json.loads(body)["results"]
        if row.get("tag_last_pushed")
    ]


def scanned_files(root: Path) -> list[tuple[str, str]]:
    names = subprocess.run(["git", "ls-files", "-z"], cwd=root, check=True, capture_output=True).stdout.split(b"\0")
    files = []
    for raw in names:
        name = raw.decode()
        if not name or name.endswith(".md") or name.startswith(EXCLUDED):
            continue
        try:
            files.append((name, (root / name).read_text(encoding="utf-8")))
        except (UnicodeDecodeError, FileNotFoundError, IsADirectoryError):
            continue
    return files


def main() -> None:
    now = dt.datetime.now(dt.timezone.utc)
    found = pins(scanned_files(ROOT))
    if not found:
        sys.exit("image-freshness check: found no pinned image, so it checked nothing")
    failed = 0
    for (registry, path, hub, tag, digest), where in sorted(found.items()):
        label = f"{registry}/{path}:{tag} ({', '.join(sorted(where))})"
        try:
            hub_digest, hub_pushed = hub_tag(hub, tag)
            state, notes = verdict(
                digest, hub_digest, hub_pushed, mirror_digest(registry, path, tag), newer_releases(tag, hub_releases(hub, tag)), now
            )
        except (OSError, ValueError, KeyError) as error:
            print(f"ERROR  {label}: could not be checked: {error}", file=sys.stderr)
            failed += 1
            continue
        print(f"{state:<6} {label}" + "".join(f"\n         {note}" for note in notes))
        failed += state == "DRIFT"
    if failed:
        sys.exit(
            f"image-freshness check FAILED: {failed} pin(s) behind Docker Hub or not checkable. Bump each to the "
            "digest Docker Hub serves once the mirror serves the same one (docker buildx imagetools inspect)."
        )
    print(f"image-freshness check: {len(found)} pinned images are current or held")


if __name__ == "__main__":
    main()
