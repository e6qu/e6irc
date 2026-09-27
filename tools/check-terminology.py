#!/usr/bin/env python3
"""Every abbreviation the prose uses is defined in docs/terminology.md.

The glossary's binding convention (AGENTS.md, docs/terminology.md): prefer the
spelled-out term, and define every abbreviation there. This guard reads the
prose a person reads — every Markdown file and every code comment — finds each
all-capitals token of two to six characters, and fails on one that the glossary
does not define and that is not one of the known non-abbreviations below (an
IRC command, an SQL keyword, a file name, a word in capitals for emphasis).

Code is not prose: fenced blocks, `inline code` spans, and link targets are
skipped, so an identifier quoted as code never needs a definition. A term the
glossary defines is one written in bold there, alone or as one of its
spellings: `**TLS**`, `**Transport Layer Security (TLS)**`,
`**Bouncer / BNC**`.

    python3 tools/check-terminology.py
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
GLOSSARY = Path("docs/terminology.md")

# Directories whose files are not this repository's prose: build output,
# installed packages, vendored third-party sources, agent worktrees.
SKIPPED_DIRECTORIES = {".git", ".claude", "target", "node_modules", "dist", "vendor"}
# A migration is checksum-pinned (docs/terminology.md, "Migration";
# tools/check-migration-integrity.sh): editing a comment in an applied one
# would refuse every database that already ran it, so its words are history,
# not prose this guard may ask to change.
SKIPPED_TOP_LEVEL = {"migrations"}

LINE_COMMENT = {
    ".rs": "//",
    ".js": "//",
    ".mjs": "//",
    ".sh": "#",
    ".py": "#",
    ".toml": "#",
    ".yml": "#",
    ".yaml": "#",
    ".sql": "--",
}

# An all-capitals token of two to six letters or digits, starting with a
# letter, that is a word of its own: not part of a path, an identifier, a
# flag, or a longer token. The first part of a hyphenated compound counts
# (`UTF-8`, `SHA-256`, `TLS-terminating`).
TOKEN = re.compile(r"(?<![\w\-/.$`@#:=+])([A-Z][A-Z0-9]{1,5})(?!\w)")
FENCE = re.compile(r"^\s*(```|~~~)")
CODE_SPAN = re.compile(r"`[^`\n]*`")
PARAGRAPH_CODE_SPAN = re.compile(r"`(?:[^`\n]|\n(?![ \t]*\n))*`")
LINK_TARGET = re.compile(r"\]\([^)\s]*\)")
URL = re.compile(r"\bhttps?://\S+")
BOLD = re.compile(r"\*\*(.+?)\*\*", re.S)
# A code point written in hexadecimal (`FFFD`, `C0`, `A0`) names a character,
# not an abbreviation; so does a hex digit run.
HEXADECIMAL = re.compile(r"[0-9A-F]{2,6}")

# Words in capitals that are not abbreviations. Each group says why.
NOT_ABBREVIATIONS = {
    # IRC commands, subcommands, numerics' names, modes, capabilities and
    # ISUPPORT tokens: the protocol's own words, spelled as the wire spells
    # them.
    "irc protocol": """
        ACCEPT ACCESS ACK ACTION ADD ADMIN AFTER AROUND AWAY BATCH BEFORE
        BETWEEN CAP CHANMODES CHANTYPES CHATHISTORY CLEAR CONNECT DEL DEOP DIE
        DLINE DROP END ENFORCE ERROR EXTBAN FAIL FLAGS FOUNDER GHOST GROUP HELP
        HELPOP IDENTIFY INFO INVEX INVITE ISON JOIN KEEPTOPIC KICK KILL KLINE
        KNOCK LATEST LINKS LIST LOGOUT LS LUSERS MARKREAD MLOCK MODE MODES
        MONITOR MOTD NAK NAMES NEW NICK NICKLEN NOTE NOTICE OPER PART PASS PING
        PONG PREFIX PRIVMSG QUIT REGAIN REGISTER REHASH REQ RESUME SAFELIST
        SASL SET SETHOST STATS STATUSMSG SUCCESSOR TAGMSG TARGETS TIME TOPIC
        TOPICLEN UNGROUP USER USERIP USERS VERIFY VERSION VOICE WALLOPS WARN
        WHO WHOIS WHOWAS WHOX XLINE KEYLEN BANLEN ELIST CASEMAPPING CHANLIMIT
        MAXLIST NETWORK AWAYLEN KICKLEN MAXTARGETS TARGMAX MONITOR UTF8ONLY
        AOP VOP OP RELAYMSG DEBUG READY UNKLINE UNDLINE UNXLINE KEY LIMIT
        OWN SHARE LINE HELLO ON OFF ALL CHECK ONLY PLAIN EXTERNAL
        """,
    # SQL keywords and types, as they are written in the statements the
    # comments describe.
    "sql": """
        SELECT INSERT UPDATE DELETE WHERE FROM INTO VALUES UNIQUE NULL NOT
        AND OR IS SKIP LOCKED DESC ASC BIGINT UNNEST COPY FOR ANY ORDER BY
        RETURNING RETURN CREATE INDEX TABLE ALTER DROP BEGIN COMMIT ROLLBACK
        THEN CASE WHEN ELSE LIKE TEXT BYTEA PRIMARY KEY CHECK DEFAULT
        """,
    # HTTP methods and status words.
    "http": "GET POST PUT PATCH DELETE HEAD OPTIONS OK",
    # File names and repository documents referred to by their stem.
    "file names": "AGENTS DESIGN PLAN README BUGS LICENSE CLAUDE",
    # English words written in capitals for emphasis, or as the words of an
    # all-capitals heading or rule name.
    "emphasis": """
        HARD RULE MUST MAY NO ONE SAME OTHER EVERY WITH BOTH WHOLE WRONG
        STORED THIRD OLD OPEN CLOSE DID EACH NAMED KEEP MODIFY GUARD STOP
        SAFETY ENDOF PRED ALICE UN IT AN AS AT BE DO GO IF IN OF SO TO UP US
        WE
        """,
    # Placeholders in a usage line or a `SAFETY:` note, standing for a value.
    "placeholders": "ADDR BASE BURST CODE COUNTS DIGEST DIR FILE HOST IMAGE NAME PATH PORT REASON TARGET TOKEN",
    # Proper names spelled in capitals by their owners, not abbreviations of
    # anything this repository means: products (LLVM and QEMU are no longer
    # expansions; GNU is a recursive name; ZNC is a bouncer), licences by
    # their SPDX identifiers, the RSA algorithm by its inventors, the OFTC
    # network, the KOI8-R character set, and the TEST-NET documentation
    # address ranges (RFC 5737).
    "names": "GNU LLVM QEMU ZNC MIT MPL NCSA RSA OFTC KOI8 TEST",
    # Operating-system signal and error names, spelled as the system spells them.
    "system names": "SIGHUP SIGINT SIGTERM SIGKILL EMFILE ENFILE EPERM EINTR EOF",
    # Unicode's names for its control and directional characters.
    "unicode names": "NUL BEL ESC DEL LRE RLE PDF LRO RLO LRI RLI FSI PDI CR LF",
}
KNOWN_WORDS = {word for words in NOT_ABBREVIATIONS.values() for word in words.split()}


def defined_terms(glossary: str) -> set[str]:
    """The abbreviations the glossary defines: each bold span, and each of its
    spellings split on ` / ` and parentheses."""
    terms: set[str] = set()
    for span in BOLD.findall(glossary):
        for part in re.split(r"\s*/\s*|\s*\(\s*|\s*\)\s*", span):
            part = part.strip().strip("`")
            if part:
                terms.add(part)
    return terms


def prose_lines(path: Path, text: str):
    """(line number, prose) for each line of a file that a person reads as
    prose: all of Markdown outside code, and the comments of source files."""
    suffix = path.suffix
    if suffix == ".md":
        fenced = False
        kept = []
        for line in text.splitlines():
            if FENCE.match(line):
                fenced = not fenced
                kept.append("")
            else:
                kept.append("" if fenced else line)
        # A code span may wrap onto the next line of its paragraph; blank it
        # whole, keeping its line breaks so line numbers stay true.
        prose = PARAGRAPH_CODE_SPAN.sub(
            lambda span: "\n" * span.group(0).count("\n"), "\n".join(kept)
        )
        yield from enumerate(prose.split("\n"), 1)
        return
    if suffix == ".html":
        for match in re.finditer(r"<!--(.*?)-->", text, re.S):
            first = text.count("\n", 0, match.start()) + 1
            for offset, line in enumerate(match.group(1).splitlines()):
                yield first + offset, line
        return
    if path.name == "Dockerfile":
        marker = "#"
    else:
        marker = LINE_COMMENT.get(suffix)
    if marker is None:
        return
    block = False
    for number, line in enumerate(text.splitlines(), 1):
        if suffix in (".rs", ".js", ".mjs"):
            if block:
                end = line.find("*/")
                yield number, line if end < 0 else line[:end]
                block = end < 0
                continue
            start = line.find("/*")
            if start >= 0 and (start == 0 or line[start - 1] in " \t"):
                end = line.find("*/", start + 2)
                yield number, line[start + 2 : end if end >= 0 else None]
                block = end < 0
                continue
        at = line.find(marker)
        while at >= 0 and at > 0 and line[at - 1] not in " \t":
            at = line.find(marker, at + 1)
        if at >= 0:
            yield number, line[at + len(marker) :]


def undefined_abbreviations(root: Path) -> dict[str, list[str]]:
    """Each undefined abbreviation, with the `path:line` of every use."""
    glossary = (root / GLOSSARY).read_text(encoding="utf-8")
    defined = defined_terms(glossary)
    found: dict[str, list[str]] = {}
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if any(part in SKIPPED_DIRECTORIES for part in relative.parts[:-1]):
            continue
        if relative.parts[0] in SKIPPED_TOP_LEVEL:
            continue
        if not path.is_file():
            continue
        if path.suffix not in LINE_COMMENT and path.suffix not in (".md", ".html"):
            if path.name != "Dockerfile":
                continue
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in prose_lines(relative, text):
            line = URL.sub(" ", LINK_TARGET.sub("]", CODE_SPAN.sub(" ", line)))
            for match in TOKEN.finditer(line):
                token = match.group(1)
                if token in defined or token in KNOWN_WORDS:
                    continue
                if HEXADECIMAL.fullmatch(token) and any(c.isdigit() for c in token):
                    continue
                found.setdefault(token, []).append(f"{relative}:{number}")
    return found


def main() -> int:
    found = undefined_abbreviations(ROOT)
    if not found:
        return 0
    print(
        f"{len(found)} abbreviation(s) used but not defined in {GLOSSARY}. Spell each "
        "out where it is used, or add a glossary entry that writes it in bold "
        "(see the file's convention); a word in capitals that is not an "
        "abbreviation belongs in NOT_ABBREVIATIONS in this script, with its group:",
        file=sys.stderr,
    )
    for token, uses in sorted(found.items(), key=lambda item: (-len(item[1]), item[0])):
        shown = ", ".join(uses[:5]) + (f", … ({len(uses)} uses)" if len(uses) > 5 else "")
        print(f"  {token}: {shown}", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
