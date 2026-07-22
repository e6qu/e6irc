#!/usr/bin/env bash
# check-dead-pub.sh — catch `pub` items that only tests keep alive.
#
# check-dead-code.sh already catches private and `pub(crate)` items used only by
# tests (it builds the shipped artifacts with cfg(test) off, so the compiler's
# dead_code lint fires). But rustc's dead_code analysis is per-crate and treats
# a library's fully-`pub` items as reachable API — so a `pub` item in a lib that
# ONLY an integration test (a separate crate) references is invisible to it.
# That is the last way test coverage can mask dead code, and this guard closes
# it: a `pub` item defined in shipped source but referenced nowhere else in
# shipped source is dead in the binary, kept alive only by tests.
#
# These crates are a self-contained workspace (nothing publishes them), so there
# is no "external API" category — an unreferenced `pub` item is genuinely dead,
# not a consumer-facing export. If a real case ever needs to stay `pub` while
# unreferenced in shipped code, mark it with a `// dead-pub-allow: <reason>`
# comment on the definition line or the line above (explicit and justified — no
# silent suppression).
#
# Textual analysis (not a compiler pass), kept conservative so it only ever errs
# toward MISSING dead code, never toward flagging live code: it counts
# word-boundary occurrences, so anything referenced through a trait call, field
# access, re-export, or function pointer is seen as used. python3 is present on
# every CI runner and dev machine; no extra dependency.

set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import re, glob, sys

# Shipped source only: crate src, minus any tests/ subtree.
files = [f for f in glob.glob("crates/**/src/**/*.rs", recursive=True)
         if "/tests/" not in f]
texts = {f: open(f, encoding="utf-8", errors="replace").read() for f in files}
def code_only(text: str) -> str:
    """Source with comments and string literals blanked out.

    The reference count below is textual, so a name merely *mentioned* in a doc
    comment (or inside a string) would look like a use and hide a genuinely dead
    item. Blanking them first means the guard counts calls, not prose.
    """
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

# Definitions and the `dead-pub-allow` marker are read from the original text
# (the marker lives in a comment); only the reference count uses the stripped
# form, so prose cannot keep a dead item alive.
allsrc = "\n".join(code_only(t) for t in texts.values())

# Fully-`pub` item definitions (not pub(crate) — those are the compiler gate's
# job): fn/struct/enum/const/static/type/trait.
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
        # Explicit, justified exemption on the def line or the line above.
        if allow in line or (i > 0 and allow in lines[i - 1]):
            continue
        # Referenced elsewhere in shipped source? (def counts as 1 occurrence)
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
