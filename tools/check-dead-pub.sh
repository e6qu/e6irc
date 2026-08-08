#!/usr/bin/env bash
# Catch fully public items kept alive only by tests.
# Use `dead-pub-allow: reason` on a justified exception.

set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, glob, sys

files = [f for f in glob.glob("crates/**/src/**/*.rs", recursive=True)
         if "/tests/" not in f]
texts = {f: open(f, encoding="utf-8", errors="replace").read() for f in files}
def code_only(text: str) -> str:
    """Blank comments and strings before counting references."""
    out, i, n = [], 0, len(text)
    while i < n:
        c = text[i]
        if c == '/' and i + 1 < n and text[i + 1] == '/':
            j = text.find('\n', i)
            i = n if j == -1 else j
        elif c == '/' and i + 1 < n and text[i + 1] == '*':
            j = text.find('*/', i + 2)
            i = n if j == -1 else j + 2
        elif c == '"':
            i += 1
            while i < n and text[i] != '"':
                i += 2 if text[i] == '\\' else 1
            i += 1
        else:
            out.append(c)
            i += 1
    return ''.join(out)

allsrc = "\n".join(code_only(t) for t in texts.values())

defre = re.compile(r'\bpub\s+(?:fn|struct|enum|const|static|type|trait)\s+([A-Za-z_][A-Za-z0-9_]*)')
allow = "dead-pub-allow"

dead = []
for f, t in texts.items():
    lines = t.splitlines()
    for i, line in enumerate(lines):
        m = defre.search(line)
        if not m:
            continue
        name = m.group(1)
        if allow in line or (i > 0 and allow in lines[i - 1]):
            continue
        if len(re.findall(r'\b' + re.escape(name) + r'\b', allsrc)) <= 1:
            dead.append((f, i + 1, name))

if dead:
    print("dead-pub guard FAILED: `pub` item(s) referenced only by tests (or "
          "nowhere) in shipped source — remove them, tighten to pub(crate), or "
          "wire them in. Mark a genuine exception with `// dead-pub-allow: why`.\n",
          file=sys.stderr)
    for f, ln, name in sorted(dead):
        print(f"  {name}  {f}:{ln}", file=sys.stderr)
    sys.exit(1)

print("dead-pub guard: clean (no pub item kept alive only by tests)")
PY
