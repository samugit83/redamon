"""Priority Board group keys read the fields the writers store (S-13).

A fix item is one group key. For cache poisoning, subdomain takeover, GraphQL
and the AI sources, `grouping.group_key` keys on properties the
"vulnerabilities" finding query has to project: `cache_technique` +
`cache_header` / `cache_param`, `takeover_provider`, `vulnerability_type`,
`ai_owasp_llm_id` + `ai_payload_class`. Reading names no writer stores (or not
projecting the right ones) gave every finding of a source one key (`cache::`,
`takeover::cname`, `graphql:`, `ai::`), so one fix item swallowed the family.

The rows here are what the board really sees: the real writer's properties
(fake session) passed through the real finding query's `v.<prop> AS <alias>`
projection and normalise_finding_row. The node's full property map is checked
too, so the verdict does not depend on how the projection is simulated.

Run: ./agentic/run_tests.sh tests/test_triage_group_key_stored_fields.py
"""
from __future__ import annotations

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_AGENTIC = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_REPO = os.path.dirname(_AGENTIC)
for _p in ("/repo", "/repo/agentic", _AGENTIC, _REPO, os.path.join(_REPO, "scanners")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from ai_attack_surface_scan.normalizer import Finding as AiAttackFinding  # noqa: E402
from ai_attack_surface_scan.normalizer import write_finding as write_ai_attack_finding  # noqa: E402
from cypherfix_triage import evidence  # noqa: E402
from cypherfix_triage.fact_queries import FINDING_QUERIES, normalise_finding_row  # noqa: E402
from cypherfix_triage.grouping import assign_groups, group_key  # noqa: E402
from cypherfix_triage.score_model import detector_key  # noqa: E402
from graph_db.mixins.cache_mixin import CacheMixin  # noqa: E402
from graph_db.mixins.graphql_mixin import GraphQLMixin  # noqa: E402
from graph_db.mixins.recon.ai_surface_recon_mixin import AiSurfaceReconMixin  # noqa: E402
from graph_db.mixins.recon.takeover_mixin import TakeoverMixin  # noqa: E402


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(CacheMixin, TakeoverMixin, AiSurfaceReconMixin, GraphQLMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def vuln_props(self) -> list:
        return [p["props"] for q, p in self.session.calls
                if "MERGE (v:Vulnerability" in q and isinstance(p.get("props"), dict)]


_VULN_QUERY = next(q["query"] for q in FINDING_QUERIES if q["name"] == "vulnerabilities")
_PROJECTION = re.findall(r"(?<![\w.])v\.(\w+) AS (\w+)", _VULN_QUERY)
_GROUP_COLUMNS = ("cache_technique", "cache_header", "cache_param", "takeover_provider",
                  "vulnerability_type", "ai_owasp_llm_id", "ai_payload_class")


def _board_row(props: dict, without=()) -> dict:
    """The row the board scores: the query's plain `v.x AS y` columns."""
    row = {alias: props.get(prop) for prop, alias in _PROJECTION if alias not in without}
    row["label"] = "Vulnerability"
    return normalise_finding_row(row)


def _cache_props() -> list:
    w = _Writer()
    w.update_graph_from_cache_scan({"cache_scan": {"findings": [
        {"endpoint_url": "https://app.example.test/", "technique": "unkeyed_header",
         "cache_header": "X-Forwarded-Host", "vector_type": "header", "impact": "redirect",
         "confidence_tier": "Confirmed", "severity": "high"},
        {"endpoint_url": "https://app.example.test/search", "technique": "param_cloaking",
         "cache_param": "utm_content", "vector_type": "param", "impact": "xss",
         "confidence_tier": "Strong", "severity": "high"},
        # The first problem again on another host: the same fix.
        {"endpoint_url": "https://www.example.test/", "technique": "unkeyed_header",
         "cache_header": "X-Forwarded-Host", "vector_type": "header", "impact": "redirect",
         "confidence_tier": "Confirmed", "severity": "high"},
    ]}}, "u1", "p1")
    props = w.vuln_props()
    assert len(props) == 3
    return props


def _takeover_props() -> list:
    w = _Writer()
    w.update_graph_from_subdomain_takeover({"domain": "example.test", "subdomain_takeover": {"findings": [
        {"id": "takeover_a", "hostname": "docs.example.test", "takeover_provider": "github-pages",
         "takeover_method": "cname", "verdict": "likely", "severity": "high"},
        {"id": "takeover_b", "hostname": "shop.example.test", "takeover_provider": "shopify",
         "takeover_method": "cname", "verdict": "likely", "severity": "high"},
    ]}}, "u1", "p1")
    props = w.vuln_props()
    assert len(props) == 2
    return props


def _graphql_props() -> list:
    w = _Writer()
    w.update_graph_from_graphql_scan({"graphql_scan": {"endpoints": {}, "vulnerabilities": [
        {"endpoint": "https://api.example.test/graphql", "source": "graphql_scan",
         "vulnerability_type": "graphql_introspection_enabled", "severity": "medium",
         "title": "Introspection enabled"},
        {"endpoint": "https://api.example.test/graphql", "source": "graphql_scan",
         "vulnerability_type": "graphql_batching_enabled", "severity": "low",
         "title": "Batching enabled"},
    ]}}, "u1", "p1")
    props = w.vuln_props()
    assert len(props) == 2
    return props


def _ai_surface_props() -> list:
    w = _Writer()
    stats = {"vulnerabilities_created": 0, "relationships_created": 0, "errors": []}
    for fid, owasp in (("aisr_a", "LLM01"), ("aisr_b", "LLM07")):
        try:
            w._aisr_write_finding(w.session, {"id": fid, "type": "x", "name": fid,
                                              "owasp_llm_id": owasp}, "u1", "p1", stats)
        except Exception:  # noqa: BLE001 - only the MERGE props matter here
            pass
    props = w.vuln_props()
    assert len(props) == 2
    return props


def _ai_attack_props() -> list:
    session = _Session()
    for chip, owasp, payload in (("jailbreak", "LLM01", "garak-dan"),
                                 ("prompt-injection", "LLM01", "garak-promptinject")):
        try:
            write_ai_attack_finding(session, AiAttackFinding(
                source="garak", chip=chip, name=chip, baseurl="https://llm.example.test",
                path="/v1/chat", ai_owasp_llm_id=owasp, ai_payload_class=payload), "u1", "p1")
        except Exception:  # noqa: BLE001 - only the MERGE props matter here
            pass
    props = [p["props"] for q, p in session.calls
             if "MERGE (v:Vulnerability" in q and isinstance(p.get("props"), dict)]
    assert len(props) == 2
    return props


class Projection(unittest.TestCase):
    def test_projection_was_parsed(self):
        self.assertIn(("source", "source"), _PROJECTION)
        self.assertIn(("takeover_method", "takeover_method"), _PROJECTION)

    def test_the_group_key_fields_are_projected_under_their_stored_names(self):
        for column in _GROUP_COLUMNS:
            self.assertIn((column, column), _PROJECTION)


class CacheGroupKey(unittest.TestCase):
    def test_two_cache_problems_are_two_groups_on_the_board(self):
        header, param, header_again = (group_key(_board_row(p)) for p in _cache_props())
        self.assertNotEqual(header, param, f"both cache findings share the key {header!r}")
        self.assertEqual(header, "cache:unkeyed_header:x-forwarded-host")
        self.assertEqual(param, "cache:param_cloaking:utm_content")
        # The host is a member, not part of the key.
        self.assertEqual(header_again, header)

    def test_even_the_full_node_gives_two_groups(self):
        a, b, _ = (group_key(dict(p, label="Vulnerability")) for p in _cache_props())
        self.assertNotEqual(a, b, f"both cache findings share the key {a!r}")

    def test_assign_groups_makes_two_fix_items(self):
        rows = [dict(_board_row(p), score=50.0, risk=0.5, tier="T3", state="open")
                for p in _cache_props()]
        groups = assign_groups(rows)
        self.assertEqual(sorted(len(g["members"]) for g in groups.values()), [1, 2])

    def test_a_deception_finding_keys_on_its_url_shape(self):
        w = _Writer()
        w.update_graph_from_cache_scan({"cache_scan": {"findings": [
            {"endpoint_url": "https://app.example.test/account", "technique": "cache_deception",
             "vector_type": "path", "cache_header": "", "cache_param": "static-suffix:/.css",
             "impact": "deception", "confidence_tier": "Confirmed", "severity": "high"},
        ]}}, "u1", "p1")
        (props,) = w.vuln_props()
        self.assertEqual(group_key(_board_row(props)), "cache:cache_deception:static-suffix:/.css")


class SiblingKeys(unittest.TestCase):
    def test_two_takeover_providers_are_two_groups(self):
        a, b = (group_key(_board_row(p)) for p in _takeover_props())
        self.assertNotEqual(a, b, f"both takeovers share the key {a!r}")
        self.assertEqual((a, b), ("takeover:github-pages:cname", "takeover:shopify:cname"))

    def test_two_graphql_checks_are_two_groups(self):
        a, b = (group_key(_board_row(p)) for p in _graphql_props())
        self.assertNotEqual(a, b, f"both GraphQL findings share the key {a!r}")
        self.assertEqual(a, "graphql:graphql_introspection_enabled")

    def test_two_ai_owasp_classes_are_two_groups(self):
        a, b = (group_key(_board_row(p)) for p in _ai_surface_props())
        self.assertNotEqual(a, b, f"both AI findings share the key {a!r}")
        self.assertEqual(a, "ai:llm01:mcp_static")

    def test_two_ai_attack_payload_classes_are_two_groups(self):
        a, b = (group_key(_board_row(p)) for p in _ai_attack_props())
        self.assertNotEqual(a, b, f"both AI attack findings share the key {a!r}")
        self.assertEqual((a, b), ("ai:llm01:garak-dan", "ai:llm01:garak-promptinject"))


class OlderNodes(unittest.TestCase):
    """A node without the fields is its own group, never one bucket per source."""

    def _keys(self, source: str) -> tuple:
        return tuple(group_key({"label": "Vulnerability", "source": source, "id": fid})
                     for fid in ("vuln_a", "vuln_b"))

    def test_each_source_falls_back_to_the_finding_itself(self):
        for source in ("cache_poisoning", "takeover_scan", "graphql_scan", "ai_surface_recon", "garak"):
            with self.subTest(source=source):
                self.assertEqual(self._keys(source), ("finding:vuln_a", "finding:vuln_b"))

    def test_a_partial_key_still_groups(self):
        # An older deception node stored no vector; its technique is still one fix.
        self.assertEqual(group_key({"source": "cache_poisoning", "id": "x",
                                    "cache_technique": "cache_deception"}),
                         "cache:cache_deception:")


class WhatTheNewColumnsDoNotMove(unittest.TestCase):
    """The columns are for grouping: no review expires and no prior re-keys,
    except the AI Surface detector, which read `ai_owasp_llm_id` all along."""

    def _all_rows(self):
        return (_cache_props() + _takeover_props() + _graphql_props()
                + _ai_surface_props() + _ai_attack_props())

    def test_the_evidence_bundle_and_its_hash_are_unchanged(self):
        for props in self._all_rows():
            with self.subTest(source=props.get("source"), id=props.get("id")):
                before = _board_row(props, without=_GROUP_COLUMNS)
                after = _board_row(props)
                self.assertEqual(evidence.build_bundle(after), evidence.build_bundle(before))

    def test_detectors_are_unchanged_except_ai_surface_recon(self):
        for props in self._all_rows():
            before = detector_key(_board_row(props, without=_GROUP_COLUMNS))
            after = detector_key(_board_row(props))
            with self.subTest(source=props.get("source"), id=props.get("id")):
                if props.get("source") == "ai_surface_recon":
                    self.assertEqual(before, "ai_surface_recon")
                    self.assertEqual(after, f"ai_surface_recon:{props['ai_owasp_llm_id'].lower()}")
                else:
                    self.assertEqual(after, before)
                    self.assertEqual(after, props.get("source"))


if __name__ == "__main__":
    unittest.main()
