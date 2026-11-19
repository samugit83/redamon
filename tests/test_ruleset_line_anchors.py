"""Rulesets cite a symbol, never a line number; a doc's line anchor lands on its symbol.

`file#L123` in a SKILL.md or AGENTS.md points at whatever line 123 holds after
the next edit; 19 such links pointed at unrelated code before the fix pass
named the function, Cypher or volume instead.

The subsystem docs under docs/readmes/ may still use `[`symbol`](file#L123)`,
so there the anchor must stay where the symbol is (drift-map #118: two dozen
had drifted onto unrelated code with nothing failing).
"""
import os
import re
import shutil
import subprocess
from pathlib import Path
from urllib.parse import unquote

import pytest

REPO = Path(__file__).resolve().parents[1]
LINE_ANCHOR = re.compile(r"\]\([^)\s]*#L\d+")


def _git_ls_files(*patterns):
    if shutil.which("git") is None or not (REPO / ".git").exists():
        pytest.skip("needs git and the repository's .git")
    return subprocess.run(["git", "-C", str(REPO), "ls-files", *patterns],
                          capture_output=True, text=True, check=True).stdout.split()


def test_no_ruleset_links_a_line_number():
    files = _git_ls_files("skills/*/SKILL.md", "*AGENTS.md")
    assert files, "no SKILL.md or AGENTS.md found"
    hits = [
        f"{name}:{i}: {line.strip()[:120]}"
        for name in files
        for i, line in enumerate((REPO / name).read_text(encoding="utf-8").split("\n"), 1)
        if LINE_ANCHOR.search(line)
    ]
    assert hits == [], "cite the symbol instead of a line number:\n" + "\n".join(hits)


#: `[`name`](path#L12)`, also `#L12-L20`, a blob URL, or an unquoted name that
#: reads as code (an underscore, a call or camelCase), never a bare word.
_SYMBOL_LINK = re.compile(
    r"\[(?:`(?P<ticked>[A-Za-z_$][\w.$]*(?:\(\))?)`|(?P<bare>[A-Za-z_$][\w.$]*(?:\(\))?))\]"
    r"\(\s*<?(?P<path>[^)\s>#]+)#L(?P<line>\d+)(?:-L?\d+)?>?\s*\)")
_CODE_LIKE = re.compile(r"[_($]|[a-z][A-Z]")
#: `capture_lib.py` or `Dockerfile` is a file, so the anchor is a bare line number
#: with nothing to check it against.
_FILE_NAME = re.compile(r"\.(?:py|ts|tsx|js|mjs|cjs|json|ya?ml|md|sh|prisma|toml|txt|ini|cfg)$|^Dockerfile$")
_BLOB = re.compile(r"https://github\.com/samugit83/redamon/blob/[^/]+/(.+)")
#: A link may land on the decorator or the comment above a definition.
_SLACK = 3


def _symbol_links(doc: Path):
    for i, line in enumerate(doc.read_text(encoding="utf-8").split("\n"), 1):
        for m in _SYMBOL_LINK.finditer(line):
            text = m.group("ticked") or m.group("bare")
            if (m.group("bare") and not _CODE_LIKE.search(text)) or _FILE_NAME.search(text):
                continue
            blob = _BLOB.match(m.group("path"))
            if blob:
                dest = REPO / unquote(blob.group(1))
            elif re.match(r"^[a-z][a-z0-9+.-]*:", m.group("path"), re.I):
                continue
            else:
                dest = (doc.parent / unquote(m.group("path"))).resolve()
            yield i, text, dest, int(m.group("line"))


def test_a_docs_line_anchor_lands_on_its_symbol():
    """The anchored line is within a few lines of one where the symbol is
    defined or written. Matched on the last dotted part (`Class.method` lands on
    `method`); a missing target file is the path audit's finding, not this one's."""
    docs = _git_ls_files("docs/readmes/*.md")
    assert docs, "no docs under docs/readmes/"
    stale = []
    for name in docs:
        doc = REPO / name
        for lineno, text, dest, anchor in _symbol_links(doc):
            if not dest.is_file():
                continue
            symbol = text.removesuffix("()").split(".")[-1]
            word = re.compile(rf"(?<![\w$]){re.escape(symbol)}(?![\w$])")
            lines = dest.read_text(encoding="utf-8", errors="replace").split("\n")
            written = [j for j, line in enumerate(lines, 1) if word.search(line)]
            if not any(abs(anchor - j) <= _SLACK for j in written):
                where = f"written at {written[:5]}" if written else "never written there"
                stale.append(f"{name}:{lineno}: `{text}` -> {os.path.relpath(dest, REPO)}#L{anchor}, "
                             f"but `{symbol}` is {where}")
    assert stale == [], "re-point the anchor, or cite the symbol alone:\n" + "\n".join(stale)
