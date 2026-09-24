#!/usr/bin/env bash
# Catch fully public items kept alive only by tests.
# Use `dead-pub-allow: reason` on a justified exception.
#
# "Only by tests" covers both integration tests (`crates/*/tests/`, never read)
# and inline `#[cfg(test)]` items in shipped source, which are blanked out
# before references are counted: a use inside `mod tests { .. }` keeps nothing
# alive in the shipped binary. tools/test-check-dead-pub.sh holds the contract.

set -euo pipefail
cd "$(dirname "$0")/.."

python3 - <<'PY'
import os, re, glob, sys

files = sorted(f for f in glob.glob("crates/**/src/**/*.rs", recursive=True)
               if "/tests/" not in f)
texts = {f: open(f, encoding="utf-8", errors="replace").read() for f in files}


def raw_string_end(text: str, i: int):
    """If a raw (byte) string literal starts at i, return the index past it."""
    j = i + (2 if text.startswith("br", i) else 1 if text[i] == "r" else 0)
    if j == i or (i > 0 and (text[i - 1].isalnum() or text[i - 1] == "_")):
        return None
    k = j
    while k < len(text) and text[k] == "#":
        k += 1
    if k >= len(text) or text[k] != '"':
        return None
    close = '"' + "#" * (k - j)
    end = text.find(close, k + 1)
    return len(text) if end == -1 else end + len(close)


CHAR_LIT = re.compile(r"'(?:\\(?:u\{[0-9a-fA-F]{1,6}\}|x[0-9a-fA-F]{2}|.)|[^\\'\n])'")


def code_only(text: str) -> str:
    """Blank comments, strings and char literals, keeping every newline so
    line numbers survive. Char literals matter: `'"'` would otherwise open a
    string and `'{'` would unbalance the brace matching below."""
    out, i, n = [], 0, len(text)

    def blank(a: int, b: int):
        out.append(re.sub(r"[^\n]", " ", text[a:b]))

    while i < n:
        c = text[i]
        if c == "/" and i + 1 < n and text[i + 1] == "/":
            j = text.find("\n", i)
            j = n if j == -1 else j
            blank(i, j)
            i = j
        elif c == "/" and i + 1 < n and text[i + 1] == "*":
            j = text.find("*/", i + 2)
            j = n if j == -1 else j + 2
            blank(i, j)
            i = j
        elif c in "rb" and (end := raw_string_end(text, i)) is not None:
            blank(i, end)
            i = end
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i, j + 1)
            i = j + 1
        elif c == "'" and (m := CHAR_LIT.match(text, i)):
            blank(i, m.end())
            i = m.end()
        else:
            out.append(c)
            i += 1
    return "".join(out)


# `#[cfg(PRED)]` / `#![cfg(PRED)]`; whether PRED is test-only is decided by
# `test_only` below, not by the regex.
CFG_ATTR = re.compile(r"#\s*(!?)\s*\[\s*cfg\s*\(")


def split_top(args: str):
    """Split a cfg argument list on its top-level commas."""
    parts, depth, cur = [], 0, []
    for c in args:
        if c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
        if c == "," and depth == 0:
            parts.append("".join(cur).strip())
            cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        parts.append("".join(cur).strip())
    return parts


def test_only(pred: str) -> bool:
    """True when PRED can hold only under `cfg(test)`: `test` itself, or an
    `all(..)` with a test-only member. `any(test, ..)` and `not(test)` are
    shipped code and stay counted."""
    pred = re.sub(r"\s+", "", pred)
    if pred == "test":
        return True
    if pred.startswith("all(") and pred.endswith(")"):
        return any(test_only(p) for p in split_top(pred[4:-1]))
    return False


def cfg_attrs(code: str):
    """Yield (start, end, file_level, predicate) for every cfg attribute;
    file_level marks a `#![cfg(..)]` heading the file (only other inner
    attributes before it), which gates the whole file."""
    for m in CFG_ATTR.finditer(code):
        end = skip_attr(code, code.index("[", m.start()))
        rest = code[m.end():end]  # `PRED)]` plus spacing
        pred = rest[:rest.rstrip().rstrip("]").rstrip().rfind(")")]
        file_level = m.group(1) == "!" and re.fullmatch(
            r"(?:\s|#\s*!\s*\[[^\]]*\])*", code[:m.start()]) is not None
        yield m.start(), end, file_level, pred


ATTR = re.compile(r"\s*#\s*\[")
PATH_ATTR = re.compile(r'#\s*\[\s*path\s*=\s*"([^"]*)"\s*\]')
EXTERNAL_MOD = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*;")


def skip_attr(code: str, i: int) -> int:
    """i points at the `[` of an attribute; return the index past its `]`."""
    depth = 0
    while i < len(code):
        if code[i] == "[":
            depth += 1
        elif code[i] == "]":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return i


def item_end(code: str, i: int) -> int:
    """End of the item starting at i: the `;` at depth zero before any body,
    or the `}` closing its first brace-delimited body."""
    depth = 0
    while i < len(code):
        c = code[i]
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth == 0 and c == "}":
                return i + 1
        elif c == ";" and depth == 0:
            return i + 1
        i += 1
    return i


def external_mod_file(path: str, name: str):
    stem = os.path.splitext(os.path.basename(path))[0]
    base = os.path.dirname(path)
    if stem not in ("mod", "lib", "main"):
        base = os.path.join(base, stem)
    for cand in (os.path.join(base, name + ".rs"), os.path.join(base, name, "mod.rs")):
        if os.path.exists(cand):
            return os.path.normpath(cand)
    return None


def strip_cfg_test(path: str, original: str, code: str, test_files: set) -> str:
    """Blank every test-only item (newlines kept). A test-only `mod name;`
    puts its whole file on `test_files`; a test-only `#![cfg(..)]` puts the
    file itself there."""
    attrs = [a for a in cfg_attrs(code) if test_only(a[3])]
    if any(file_level for _, _, file_level, _ in attrs):
        test_files.add(path)
        return re.sub(r"[^\n]", " ", code)
    out, pos = [], 0
    for start, i, _, _ in attrs:
        if start < pos:
            continue  # nested inside an item already blanked
        attrs_start = i
        while (a := ATTR.match(code, i)):
            i = skip_attr(code, a.end() - 1)
        ext = EXTERNAL_MOD.match(code, i)
        if ext:
            # The `#[path = ".."]` string was blanked; read it from the source.
            p = PATH_ATTR.search(original[attrs_start:i])
            f = (os.path.normpath(os.path.join(os.path.dirname(path), p.group(1)))
                 if p else external_mod_file(path, ext.group(1)))
            if f is not None and not os.path.exists(f):
                f = None
            if f is None:
                sys.exit(f"dead-pub guard: cannot resolve test-only `mod "
                         f"{ext.group(1)};` declared in {path}")
            test_files.add(f)
        end = item_end(code, i)
        out.append(code[pos:start])
        out.append(re.sub(r"[^\n]", " ", code[start:end]))
        pos = end
    out.append(code[pos:])
    return "".join(out)


test_files: set = set()
shipped = {f: strip_cfg_test(f, t, code_only(t), test_files) for f, t in texts.items()}
# A file declared by a test-only `mod x;` is test code in its entirety.
for f in test_files:
    shipped[os.path.normpath(f)] = re.sub(r"[^\n]", " ", texts.get(f, ""))
shipped = {os.path.normpath(f): s for f, s in shipped.items()}

allsrc = "\n".join(shipped.values())

# `fn` takes its qualifiers with it: without them `pub async fn run` was never
# looked at, and `pub const fn new` was read as a constant named `fn`.
defre = re.compile(r'\bpub\s+(?:(?:(?:const|async|unsafe)\s+)*fn|struct|enum|const|static|type|trait)'
                   r'\s+([A-Za-z_][A-Za-z0-9_]*)')
allow = "dead-pub-allow"

dead = []
for f, t in texts.items():
    lines = t.splitlines()
    code_lines = shipped[os.path.normpath(f)].splitlines()
    for i, line in enumerate(code_lines):
        m = defre.search(line)
        if not m:
            continue
        name = m.group(1)
        if allow in lines[i] or (i > 0 and allow in lines[i - 1]):
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
