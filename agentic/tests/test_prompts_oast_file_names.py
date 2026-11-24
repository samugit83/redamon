"""G-45: long-lived OAST and dalfox output files carry a per-workflow token.

A person's sandbox serves all of their chats and projects at once, and its `/tmp` is one
folder. An interactsh listener or a backgrounded dalfox run writes for minutes or hours,
and is read back later; with a fixed name (`/tmp/oast.log`, `/tmp/interactsh.log`,
`/tmp/dalfox.json`) a second chat's listener truncates the first one's log and its
callbacks are read as the other chat's evidence. Every such file name in the prompt,
skill and community-skill texts must therefore carry the `RUN` placeholder, and every
file that uses it must tell the model what `RUN` is.

Hermetic: scans the files on disk, stdlib only. Fails on 6a1769ae, passes after G-45.
"""

from __future__ import annotations

import re
import unittest
from pathlib import Path

_AGENTIC_DIR = Path(__file__).resolve().parent.parent
_DIRS = (_AGENTIC_DIR / "prompts", _AGENTIC_DIR / "skills", _AGENTIC_DIR / "community-skills")

# The file an interactsh listener or a dalfox run writes: `-o FILE` or `> FILE`.
_WRITER = re.compile(r"(?:interactsh-client|dalfox)\b[^\n]*?(?:-o\s+|>\s*)(/tmp/[^\s'\"`)]+)")
_RUN_DEFINED = "Replace `RUN` with a short random token"


def _texts():
    for base in _DIRS:
        for path in sorted(base.rglob("*")):
            if path.is_file() and path.suffix in (".py", ".md"):
                yield path, path.read_text(encoding="utf-8")


class OastFileNamesTest(unittest.TestCase):
    def test_every_listener_output_file_carries_the_run_token(self):
        offenders = []
        for path, text in _texts():
            for m in _WRITER.finditer(text):
                if "RUN" not in m.group(1):
                    line = text.count("\n", 0, m.start()) + 1
                    offenders.append(f"{path.relative_to(_AGENTIC_DIR)}:{line} -> {m.group(1)}")
        self.assertEqual(
            offenders, [],
            "A long-lived listener writes a fixed /tmp name that another chat in the same "
            f"sandbox would share; add the RUN token: {offenders}",
        )

    def test_a_file_using_the_token_says_what_it_is(self):
        missing = [str(path.relative_to(_AGENTIC_DIR)) for path, text in _texts()
                   if re.search(r"/tmp/[^\s'\"`]*-RUN\.", text) and _RUN_DEFINED not in text]
        self.assertEqual(missing, [], f"RUN is used but never explained in: {missing}")

    def test_the_writer_pattern_matches_what_it_guards(self):
        self.assertEqual(
            [m.group(1) for m in _WRITER.finditer(
                "interactsh-client -v -o /tmp/oast.log &\n"
                'dalfox url x -o /tmp/dalfox.json --format json\n'
                "interactsh-client -server oast.fun -json -v > /tmp/interactsh.log 2>&1 &\n")],
            ["/tmp/oast.log", "/tmp/dalfox.json", "/tmp/interactsh.log"])


if __name__ == "__main__":
    unittest.main()
