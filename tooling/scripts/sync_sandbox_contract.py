#!/usr/bin/env python3
"""Keep the three copies of the per-user Kali sandbox contract in step.

``recon_orchestrator/sandbox_contract.py`` is the one place a value is edited.
This script then

* copies it byte for byte to ``agentic/sandbox_contract.py`` (the agent image
  imports its own copy and cannot reach the orchestrator's), and
* rewrites the value of every ``export const NAME = <literal>`` of
  ``webapp/src/lib/sandbox/contract.ts`` whose NAME the Python contract also
  defines, leaving comments, types and functions untouched.

A constant new to the webapp is added to contract.ts as a placeholder line
(``export const NAME = 0``) and filled in by running this script; the name
itself is the only thing written by hand.

Usage:
    python3 tooling/scripts/sync_sandbox_contract.py          # rewrite the copies
    python3 tooling/scripts/sync_sandbox_contract.py --check  # exit 1 on drift

Standard library only: it runs the same on the host and in any image.
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CANONICAL = ROOT / "recon_orchestrator" / "sandbox_contract.py"
MIRROR = ROOT / "agentic" / "sandbox_contract.py"
TS_COPY = ROOT / "webapp" / "src" / "lib" / "sandbox" / "contract.ts"

# The width the webapp's formatter wraps at; a longer statement breaks the same
# way, so a regenerated file does not fight the formatter.
PRINT_WIDTH = 120

_EXPORT_CONST = re.compile(r"^export const ([A-Z][A-Z0-9_]*) =", re.M)
_AS_CONST = re.compile(r"[ \t]+as[ \t]+const\b")
_BARE = re.compile(r"-?[0-9][0-9_]*(?:\.[0-9_]+)?|true|false|null")


def _load_canonical(path: Path):
    spec = importlib.util.spec_from_file_location("_sync_sandbox_contract_canonical", path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _quote(value: str) -> str:
    body = value.replace("\\", "\\\\").replace("\n", "\\n").replace("\t", "\\t")
    if "'" in body and '"' not in body:
        return '"' + body + '"'
    return "'" + body.replace("'", "\\'") + "'"


def _inline(value) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return f"{value:,}".replace(",", "_") if abs(value) >= 1000 else str(value)
    if isinstance(value, str):
        return _quote(value)
    if isinstance(value, (tuple, list)):
        return "[" + ", ".join(_inline(v) for v in value) + "]"
    raise TypeError(f"contract value {value!r} has no TypeScript literal form")


def _render(name: str, value) -> str:
    """The text after ``export const NAME =``: the literal, wrapped as the
    formatter would."""
    as_const = isinstance(value, (tuple, list))
    one_line = _inline(value) + (" as const" if as_const else "")
    if len(f"export const {name} = {one_line}") <= PRINT_WIDTH:
        return " " + one_line
    if as_const:
        items = "".join(f"  {_inline(v)},\n" for v in value)
        return " [\n" + items + "] as const"
    return "\n  " + one_line


def _literal_end(text: str, pos: int, name: str) -> int:
    """Index just past the literal (and its ``as const``) that starts after ``pos``."""
    i = pos
    while text[i].isspace():
        i += 1
    ch = text[i]
    if ch in "'\"":
        i += 1
        while text[i] != ch:
            if text[i] == "\\":
                i += 1
            if text[i] == "\n":
                raise ValueError(f"contract.ts: unterminated string in {name}")
            i += 1
        i += 1
    elif ch == "[":
        depth, quote = 0, None
        while True:
            c = text[i]
            if quote:
                if c == "\\":
                    i += 1
                elif c == quote:
                    quote = None
            elif c in "'\"":
                quote = c
            elif c == "[":
                depth += 1
            elif c == "]":
                depth -= 1
                if depth == 0:
                    i += 1
                    break
            i += 1
    else:
        m = _BARE.match(text, i)
        if not m:
            raise ValueError(f"contract.ts: {name} is not a plain literal")
        i = m.end()
    m = _AS_CONST.match(text, i)
    return m.end() if m else i


def regenerate_ts(ts_text: str, module) -> str:
    """contract.ts with every constant the Python contract defines set to its value."""
    for name in dict.fromkeys(_EXPORT_CONST.findall(ts_text)):
        if not hasattr(module, name):
            raise ValueError(f"contract.ts has {name}, which the Python contract does not")
        match = re.search(r"^export const " + name + r" =", ts_text, re.M)
        end = _literal_end(ts_text, match.end(), name)
        ts_text = ts_text[:match.end()] + _render(name, getattr(module, name)) + ts_text[end:]
    return ts_text


def run(check: bool, canonical: Path = CANONICAL, mirror: Path = MIRROR,
        ts_copy: Path = TS_COPY) -> list[str]:
    """Rewrites the copies, or with ``check`` only reports them. Returns the names of the
    files that differed from what the canonical contract demands."""
    drifted: list[str] = []
    source = canonical.read_bytes()
    if not source:
        raise ValueError(f"{canonical} is empty")
    if not mirror.exists() or mirror.read_bytes() != source:
        drifted.append(str(mirror))
        if not check:
            mirror.write_bytes(source)

    # Line endings are not part of the contract: a CRLF checkout compares equal.
    current = ts_copy.read_bytes().decode("utf-8").replace("\r\n", "\n")
    expected = regenerate_ts(current, _load_canonical(canonical))
    if expected != current:
        drifted.append(str(ts_copy))
        if not check:
            ts_copy.write_bytes(expected.encode("utf-8"))
    return drifted


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--check", action="store_true",
                        help="write nothing; exit 1 when a copy differs from the canonical contract")
    args = parser.parse_args(argv)
    drifted = run(args.check)
    if args.check:
        if drifted:
            for path in drifted:
                print(f"out of date: {path}", file=sys.stderr)
            print("run: python3 tooling/scripts/sync_sandbox_contract.py", file=sys.stderr)
            return 1
        print("sandbox contract artifacts are up to date")
        return 0
    for path in drifted:
        print(f"updated: {path}")
    if not drifted:
        print("sandbox contract artifacts are up to date")
    return 0


if __name__ == "__main__":
    sys.exit(main())
