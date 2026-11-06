"""B26: the SSRF skill's recon queries read properties some writer sets.

They used e.parameters, p.endpoint, p.location and Technology.host, which no
writer sets, so the parameter query always came back empty. Hermetic: every
property each query reads must be declared in the schema (graph_db/
schema_sections.md, the one declaration the writer-coverage test enforces).
"""
import os
import re
import sys
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO = os.path.dirname(os.path.dirname(_HERE))
sys.path.insert(0, os.path.dirname(_HERE))

SCHEMA = open(os.path.join(_REPO, "graph_db", "schema_sections.md")).read()
PROMPT = open(os.path.join(_REPO, "agentic", "prompts", "ssrf_prompts.py")).read()
_STEP1 = PROMPT[PROMPT.index("### Step 1: Surface inventory"):PROMPT.index("If no graph data exists")]


def _declared(label: str, prop: str) -> bool:
    start = SCHEMA.index(f"**{label}**")
    nxt = re.search(r"\n\*\*[A-Z][A-Za-z]+\*\*", SCHEMA[start + 4:])
    section = SCHEMA[start: start + 4 + (nxt.start() if nxt else len(SCHEMA))]
    return bool(re.search(rf"^- {re.escape(prop)} \(|`{re.escape(prop)}`|^- {re.escape(prop)}$", section, re.M)) \
        or prop in ("user_id", "project_id")


class TestSsrfQueries(unittest.TestCase):
    def test_every_property_is_declared(self):
        aliases = {"e": "Endpoint", "p": "Parameter", "b": "BaseURL", "t": "Technology"}
        missing = []
        for alias, prop in set(re.findall(r"\b([epbt])\.([a-z_]+)\b", _STEP1)):
            if not _declared(aliases[alias], prop):
                missing.append(f"{aliases[alias]}.{prop}")
        self.assertEqual(missing, [])

    def test_the_dead_properties_are_gone(self):
        for dead in ("e.parameters", "p.endpoint ", "p.location", "t.host"):
            self.assertNotIn(dead, _STEP1)

    def test_labels_and_quarantine_are_read(self):
        self.assertIn("p.category = 'redirect_params' OR p.type = 'url'", _STEP1)
        self.assertIn("coalesce(e.quarantined, false) = false", _STEP1)
        self.assertIn("(b:BaseURL)-[:HAS_ENDPOINT]->(:Endpoint)-[:USES_TECHNOLOGY]->(t:Technology)", _STEP1)


if __name__ == "__main__":
    unittest.main()
