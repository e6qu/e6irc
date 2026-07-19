#!/usr/bin/env python3
"""Differential compatibility harness (DESIGN §7.7).

Plays identical scripted client sessions against two IRC servers
(e6ircd and a reference Solanum) and diffs the normalized transcripts.
Divergences fail the run unless whitelisted in diff_whitelist.toml with
a reason.

Usage:
    diff_sessions.py --ours HOST:PORT --reference HOST:PORT
"""

import argparse
import re
import socket
import sys
import time
import tomllib
from pathlib import Path

# Each scenario is a list of (client, line) pairs; clients are created
# on first use. Lines are sent in order with short settling pauses.
SCENARIOS = {
    "registration": [
        ("a", "NICK diffa"),
        ("a", "USER diffa 0 * :Diff A"),
    ],
    "join-topic-names": [
        ("a", "NICK diffa"),
        ("a", "USER diffa 0 * :Diff A"),
        ("a", "JOIN #diff"),
        ("a", "TOPIC #diff :hello topic"),
        ("a", "TOPIC #diff"),
        ("a", "NAMES #diff"),
        ("b", "NICK diffb"),
        ("b", "USER diffb 0 * :Diff B"),
        ("b", "JOIN #diff"),
        ("b", "PRIVMSG #diff :hi from b"),
        ("a", "MODE #diff"),
        ("a", "WHO #diff"),
    ],
    "errors": [
        ("a", "NICK diffa"),
        ("a", "USER diffa 0 * :Diff A"),
        ("a", "JOIN badname"),
        ("a", "PRIVMSG nosuchnick :hi"),
        ("a", "MODE #nosuchchan"),
        ("a", "BOGUSCMD x"),
    ],
}

NORMALIZERS = [
    (re.compile(r"^:\S+ "), ":SERVER "),  # server name differs
    (re.compile(r"\b\d{9,}\b"), "TS"),  # timestamps
    (re.compile(r"e6ircd-[\w.-]+|solanum-[\w.-]+|charybdis[\w.-]*"), "VERSION"),
]


def normalize(line: str, literals: list[str]) -> str:
    # Deployment-specific literals (server names, network names) first,
    # longest first so substrings don't shadow.
    for lit in sorted(literals, key=len, reverse=True):
        if lit:
            line = line.replace(lit, "NORM")
    for pattern, replacement in NORMALIZERS:
        line = pattern.sub(replacement, line)
    return line.rstrip()


def keep(line: str) -> bool:
    """Numerics/commands whose *presence and shape* both servers must
    agree on. Free-text server lines (MOTD contents, LUSERS counts,
    notices) are deployment-specific and excluded."""
    parts = line.split(" ")
    if len(parts) < 2:
        return False
    token = parts[1]
    interesting_numerics = {
        "001", "331", "332", "353", "366", "324", "403", "401", "421",
        "442", "461", "473", "474", "475", "482", "352", "315",
    }
    return token in interesting_numerics or token in {"JOIN", "PART", "TOPIC", "PRIVMSG", "MODE"}


def run_scenario(addr: str, script, literals: list[str]) -> list[str]:
    host, port = addr.rsplit(":", 1)
    clients: dict[str, socket.socket] = {}
    transcript: list[str] = []

    def client(name: str) -> socket.socket:
        if name not in clients:
            s = socket.create_connection((host, int(port)), timeout=5)
            s.settimeout(0.3)
            clients[name] = s
        return clients[name]

    def drain(s: socket.socket) -> None:
        try:
            while chunk := s.recv(65536):
                for raw in chunk.decode("utf-8", "replace").split("\r\n"):
                    if raw:
                        transcript.append(raw)
        except (TimeoutError, socket.timeout):
            pass

    for name, line in script:
        s = client(name)
        s.sendall((line + "\r\n").encode())
        time.sleep(0.15)
        for other in clients.values():
            drain(other)
    time.sleep(0.3)
    for s in clients.values():
        drain(s)
        s.close()
    normalized = [normalize(l, literals) for l in transcript]
    return [l for l in normalized if keep(l)]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--ours", required=True)
    parser.add_argument("--reference", required=True)
    parser.add_argument(
        "--normalize",
        default="",
        help="comma-separated deployment literals (server/network names) to strip",
    )
    args = parser.parse_args()
    literals = [x for x in args.normalize.split(",") if x]

    whitelist_path = Path(__file__).parent / "diff_whitelist.toml"
    whitelist = tomllib.loads(whitelist_path.read_text()) if whitelist_path.exists() else {}
    allowed = {entry["pattern"] for entry in whitelist.get("allow", [])}

    failures = 0
    for name, script in SCENARIOS.items():
        ours = run_scenario(args.ours, script, literals)
        reference = run_scenario(args.reference, script, literals)
        ours_only = [l for l in ours if l not in reference]
        ref_only = [l for l in reference if l not in ours]
        diverging = [
            l for l in ours_only + ref_only
            if not any(re.search(p, l) for p in allowed)
        ]
        if diverging:
            failures += 1
            print(f"=== scenario {name}: DIVERGED ===")
            for l in ours_only:
                print(f"  ours-only: {l}")
            for l in ref_only:
                print(f"  ref-only:  {l}")
        else:
            print(f"=== scenario {name}: ok ({len(ours)} lines) ===")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
