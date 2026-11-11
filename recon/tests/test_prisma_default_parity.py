"""Every Prisma @default of a recon setting equals its Python default.

A project gets the Prisma value when the creating path does not set the column
(MCP create_project, import, the form while /defaults is down) and the Python
value when it starts from /defaults (the form, a preset apply). Where the two
differ, a project's settings depend on how it was created (drift-map #12). The
agent half is agentic/tests/test_prisma_default_parity.py.

The registry's `default` is the Prisma default (registry.prisma.test.ts keeps
them equal), so it stands in for schema.prisma here.
"""
import json
import os
import sys
import unittest

_RECON = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _RECON)

_REGISTRY = os.path.join(os.path.dirname(_RECON), "recon_settings", "registry.json")

# Columns whose Prisma default differs from Python on purpose, with the reason.
_KNOWN_DIFFERENCES: dict[str, str] = {
    "userId": "no @default: every creating path sets the owner",
    "domainBatchGroups": "no @default: every creating path sets the scope",
    "ownershipToken": "@default(uuid()): a random token per project; Python has no default to share",
}


def _prisma_default(spec: dict):
    if not spec.get("has_default"):
        return None
    value = spec["default"]
    if spec.get("prisma_type") == "Json" and isinstance(value, str):
        return json.loads(value)
    return value


def _differences() -> dict[str, tuple]:
    from project_settings import DEFAULT_SETTINGS

    fields = json.load(open(_REGISTRY, encoding="utf-8"))["fields"]
    out = {}
    for column, spec in fields.items():
        key = spec.get("runtime_key")
        if not key or key not in DEFAULT_SETTINGS:
            continue
        python = DEFAULT_SETTINGS[key]
        if isinstance(python, tuple):
            python = list(python)
        prisma = _prisma_default(spec)
        if prisma != python:
            out[column] = (prisma, python)
    return out


@unittest.skipUnless(os.path.exists(_REGISTRY), "recon_settings/registry.json not in this checkout")
class TestPrismaDefaultParity(unittest.TestCase):
    def test_prisma_and_python_defaults_agree(self):
        diff = {c: v for c, v in _differences().items() if c not in _KNOWN_DIFFERENCES}
        self.assertEqual(
            diff, {},
            "Prisma @default != recon DEFAULT_SETTINGS (column: (prisma, python)); "
            "the Python value wins: set the @default to it",
        )

    def test_allowlist_names_only_live_differences(self):
        stale = sorted(set(_KNOWN_DIFFERENCES) - set(_differences()))
        self.assertEqual(stale, [], "these columns agree now: drop them from _KNOWN_DIFFERENCES")


if __name__ == "__main__":
    unittest.main()
