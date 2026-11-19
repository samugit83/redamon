"""Every copy of the finding-label set agrees with MUTEABLE_LABELS.

A finding is not one node type: it is eight labels written by eight scanners,
and every path that mutes, judges, confirms, ranks or counts findings carries
its own list of them. A label missing from one copy raises nothing: that path
just matches nothing for it, so the finding cannot be muted, judged or counted
there.

The source is MUTEABLE_LABELS in graph_db/mixins/recon/triage_mixin.py. It is
the label guard the graph layer's mute, verdict and review writes match on, and
every other copy names it as the list it mirrors. Each copy below is read from
its own file (parsed when importing it would pull the agent's API or the neo4j
driver) and compared with the constant itself, never with a list written here.

Compared by other tests, so not repeated: MUTEABLE in
graph_db/node_filters/catalog.py (tests/test_node_filters_engine.py),
FINDING_LABELS in graph_db/mixins/base_mixin.py (tests/test_ingest_then_prune.py),
and multi_mute's per-label tables (agentic/tests/test_multi_mute_kind.py,
agentic/tests/test_multi_mute_clusters.py).

Run: python -m pytest tests/test_finding_labels_mirrors.py
"""

import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
for _path in (_REPO, os.path.join(_REPO, "agentic")):
    if _path not in sys.path:
        sys.path.insert(0, _path)

from graph_db.mixins.recon.triage_mixin import (  # noqa: E402
    MUTEABLE_LABELS,
    _PROJECTED_SEVERITY_SOURCE,
)
from cypherfix_triage.fact_queries import (  # noqa: E402
    FINDING_QUERIES,
    PROJECT_FACT_QUERIES,
    STORED_LAYERS,
)
from multi_mute import POOL_LABELS  # noqa: E402

_WEBAPP_SRC = os.path.join(_REPO, "webapp", "src")

#: Labels Multi mute deliberately leaves out of its pool, with the reason.
POOL_EXCLUDED = {
    "ExploitGvm": "a confirmed exploitation: muteable by a person, never a "
                  "Multi mute seed or candidate (agentic/multi_mute/__init__.py)",
}

_QUOTED = re.compile(r"""['"]([^'"]+)['"]""")
_LABEL_UNION = re.compile(r"MATCH \(n:([A-Za-z_|\s]+?)\s*[{)]")


def _read(relpath):
    with open(os.path.join(_REPO, relpath), encoding="utf-8") as f:
        return f.read()


def _py_tuple(relpath, name):
    m = re.search(rf"^{name}\s*=\s*\((.*?)\)", _read(relpath), re.M | re.S)
    if not m:
        raise AssertionError(f"{name} not found in {relpath}")
    return _QUOTED.findall(re.sub(r"#[^\n]*", "", m.group(1)))


def _ts_list(relpath, name):
    m = re.search(
        rf"\bconst {name}\b[^=]*=\s*(?:Object\.freeze\(\s*|new Set\(\s*)?\[(.*?)\]",
        _read(relpath), re.S)
    if not m:
        raise AssertionError(f"{name} not found in {relpath}")
    return _QUOTED.findall(re.sub(r"//[^\n]*", "", m.group(1)))


def _union(cypher, where):
    """The labels of the first `MATCH (n:A|B|...)` in a query."""
    m = _LABEL_UNION.search(cypher)
    if not m:
        raise AssertionError(f"no `MATCH (n:A|B...)` label union in {where}")
    return [label.strip() for label in m.group(1).split("|")]


def _fact_query(name):
    return next(q["query"] for q in PROJECT_FACT_QUERIES if q["name"] == name)


def _report_risk_union():
    src = _read("webapp/src/lib/report/reportData.ts")
    start = src.find("function queryTriageRisks")
    if start < 0:
        raise AssertionError("queryTriageRisks not found in reportData.ts")
    return _union(src[start:], "reportData.ts queryTriageRisks")


#: (copy, how to read it, what a missing label breaks).
PYTHON_COPIES = (
    ("agentic/api.py _FINDING_LABELS",
     lambda: _py_tuple("agentic/api.py", "_FINDING_LABELS"),
     "a verdict, detail, evidence or review call for that label is refused"),
    ("agentic/orchestrator_helpers/chain_graph_writer.py _CONFIRMABLE_LABELS",
     lambda: _py_tuple("agentic/orchestrator_helpers/chain_graph_writer.py",
                       "_CONFIRMABLE_LABELS"),
     "a finding the agent proved is never linked by CONFIRMS, so never proven; "
     "an extra label is a CONFIRMS edge the score model never reads back"),
    ("agentic/cypherfix_triage/fact_queries.py FINDING_QUERIES",
     lambda: [q["label"] for q in FINDING_QUERIES],
     "the triage run never collects or ranks that label"),
    ("agentic/cypherfix_triage/fact_queries.py detector_labels query",
     lambda: _union(_fact_query("detector_labels"), "detector_labels"),
     "a person's verdicts on that label never teach its detector"),
    ("agentic/cypherfix_triage/fact_queries.py STORED_LAYERS query",
     lambda: _union(STORED_LAYERS["query"], "STORED_LAYERS"),
     "a run never reads back that label's review and decision layers"),
    ("graph_db/mixins/recon/triage_mixin.py _PROJECTED_SEVERITY_SOURCE",
     lambda: list(_PROJECTED_SEVERITY_SOURCE),
     "a batch mute of that label re-checks the raw severity and source, not "
     "the values the board ranked"),
    ("tooling/scripts/mute_provenance_cleanup.py FINDING_LABELS",
     lambda: _py_tuple("tooling/scripts/mute_provenance_cleanup.py", "FINDING_LABELS"),
     "the cleanup never reaches mutes on that label"),
    ("recon/tests/test_partial_recon_excludes_muted.py MUTEABLE",
     lambda: _py_tuple("recon/tests/test_partial_recon_excludes_muted.py", "MUTEABLE"),
     "a partial-recon query that seeds a scan from a muted finding of that "
     "label goes unnoticed"),
)

TS_COPIES = (
    ("webapp/src/lib/triage/actions.ts FINDING_LABELS",
     lambda: _ts_list("webapp/src/lib/triage/actions.ts", "FINDING_LABELS"),
     "the board's verdict, finding and evidence routes refuse that label"),
    ("webapp/src/lib/mcp/findingLabels.ts MUTEABLE_FINDING_LABELS",
     lambda: _ts_list("webapp/src/lib/mcp/findingLabels.ts", "MUTEABLE_FINDING_LABELS"),
     "MCP tools, mute targets and the reportable counts skip that label"),
    ("webapp/src/lib/muteEnforcement.test.ts MUTEABLE",
     lambda: _ts_list("webapp/src/lib/muteEnforcement.test.ts", "MUTEABLE"),
     "a webapp read of that label that ignores :Muted goes unnoticed"),
    ("webapp/src/lib/report/reportData.ts queryTriageRisks",
     _report_risk_union,
     "the report's project risk ignores that label's triage risk"),
    ("webapp/src/lib/report/reportCountable.test.ts FINDING_LABELS",
     lambda: _ts_list("webapp/src/lib/report/reportCountable.test.ts", "FINDING_LABELS"),
     "a report or Insights query of that label that ignores the board's "
     "verdict goes unnoticed"),
    ("webapp/src/lib/report/reportData.test.ts MUTEABLE",
     lambda: _ts_list("webapp/src/lib/report/reportData.test.ts", "MUTEABLE"),
     "a reportData.ts query of that label that ignores :Muted goes unnoticed"),
)


class _Mirror(unittest.TestCase):
    def assert_copies_equal_source(self, copies):
        source = set(MUTEABLE_LABELS)
        for where, read, breaks in copies:
            with self.subTest(copy=where):
                labels = read()
                self.assertEqual(len(labels), len(set(labels)), f"duplicates: {labels}")
                self.assertEqual(
                    set(labels), source,
                    f"{where} drifted from MUTEABLE_LABELS "
                    f"(only in the copy={sorted(set(labels) - source)}, "
                    f"missing from the copy={sorted(source - set(labels))}); "
                    f"a missing label means {breaks}")


class TestPythonCopies(_Mirror):
    def test_the_source_is_not_empty(self):
        """An empty source would make every comparison below vacuous."""
        self.assertTrue(MUTEABLE_LABELS)

    def test_every_copy_equals_the_source(self):
        self.assert_copies_equal_source(PYTHON_COPIES)

    def test_the_multi_mute_pool_is_the_source_minus_its_named_exclusions(self):
        self.assertLessEqual(set(POOL_EXCLUDED), set(MUTEABLE_LABELS),
                             "an exclusion names a label that is not a finding")
        self.assertEqual(len(POOL_LABELS), len(set(POOL_LABELS)))
        self.assertEqual(
            set(POOL_LABELS), set(MUTEABLE_LABELS) - set(POOL_EXCLUDED),
            "agentic/multi_mute POOL_LABELS must hold every finding label except "
            f"the ones POOL_EXCLUDED names with a reason: {POOL_EXCLUDED}")


class TestTypeScriptCopies(_Mirror):
    def setUp(self):
        if not os.path.isdir(_WEBAPP_SRC):
            self.skipTest(f"webapp sources not present ({_WEBAPP_SRC})")

    def test_every_copy_equals_the_source(self):
        self.assert_copies_equal_source(TS_COPIES)


if __name__ == "__main__":
    unittest.main()
