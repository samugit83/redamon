"""Every Prisma @default of an agent setting equals its Python default.

A project gets the Prisma value when the creating path does not set the column
(MCP create_project, import, the form while /defaults is down) and the Python
value when it starts from /defaults (the form, a preset apply). Where the two
differ, a project's settings depend on how it was created: brute force,
phishing and DoS were created ON over MCP and OFF in the form (drift-map #3,
#12). The recon half is recon/tests/test_prisma_default_parity.py.

The registry's `default` is the Prisma default (registry.prisma.test.ts keeps
them equal), so it stands in for schema.prisma here. A nullable column with no
@default matches a Python default of None.
"""
import json
import os
import sys
import unittest

_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _AGENTIC)

import project_settings as ps  # noqa: E402

_REGISTRY = os.path.join(os.path.dirname(_AGENTIC), "recon_settings", "registry.json")

# Columns whose Prisma default differs from Python on purpose, with the reason.
_KNOWN_DIFFERENCES: dict[str, str] = {}


def _prisma_default(spec: dict):
    if not spec.get("has_default"):
        return None
    value = spec["default"]
    if spec.get("prisma_type") == "Json" and isinstance(value, str):
        return json.loads(value)
    return value


def _differences() -> dict[str, tuple]:
    fields = json.load(open(_REGISTRY, encoding="utf-8"))["fields"]
    out = {}
    for key, column in ps.AGENT_SETTING_COLUMNS.items():
        spec = fields.get(column)
        if spec is None:
            continue
        python = ps.DEFAULT_AGENT_SETTINGS[key]
        if isinstance(python, tuple):
            python = list(python)
        prisma = _prisma_default(spec)
        if prisma != python:
            out[column] = (prisma, python)
    return out


@unittest.skipUnless(os.path.exists(_REGISTRY), "recon_settings/registry.json not in this checkout")
class TestPrismaDefaultParity(unittest.TestCase):
    def test_every_mapped_column_is_in_the_registry(self):
        fields = json.load(open(_REGISTRY, encoding="utf-8"))["fields"]
        missing = sorted(c for c in ps.AGENT_SETTING_COLUMNS.values() if c not in fields)
        self.assertEqual(missing, [], "a column the parity check cannot see")

    def test_prisma_and_python_defaults_agree(self):
        diff = {c: v for c, v in _differences().items() if c not in _KNOWN_DIFFERENCES}
        self.assertEqual(
            diff, {},
            "Prisma @default != DEFAULT_AGENT_SETTINGS (column: (prisma, python)); "
            "the Python value wins: set the @default to it",
        )

    def test_allowlist_names_only_live_differences(self):
        stale = sorted(set(_KNOWN_DIFFERENCES) - set(_differences()))
        self.assertEqual(stale, [], "these columns agree now: drop them from _KNOWN_DIFFERENCES")

    def test_risky_skills_default_off_in_prisma(self):
        fields = json.load(open(_REGISTRY, encoding="utf-8"))["fields"]
        built_in = _prisma_default(fields["attackSkillConfig"])["builtIn"]
        for skill in ("brute_force_credential_guess", "phishing_social_engineering", "denial_of_service"):
            self.assertIs(built_in[skill], False, skill)

    def test_cve_exploit_starts_off_in_both_layers(self):
        """U2 (§12, R-240): CVE (MSF) is off in new projects, however they are created."""
        fields = json.load(open(_REGISTRY, encoding="utf-8"))["fields"]
        self.assertIs(_prisma_default(fields["attackSkillConfig"])["builtIn"]["cve_exploit"], False)
        self.assertIs(ps.DEFAULT_AGENT_SETTINGS["ATTACK_SKILL_CONFIG"]["builtIn"]["cve_exploit"], False)


if __name__ == "__main__":
    unittest.main()
