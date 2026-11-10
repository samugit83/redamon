"""Unit tests for RouteExposureMixin (plan §7.1, §15).

Hermetic: a fake neo4j session records every statement and its parameters, so
the tenant MERGE key, the flat properties, the identity-only id, the Jev clear,
the literal anon_status SET and the declared-only clear are asserted without a
live graph.
"""

import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.mixins.recon.route_exposure_mixin import (  # noqa: E402
    RouteExposureMixin, _vuln_id, is_artifact_path,
)

BASE = "http://10.0.0.5"


class _Session:
    def __init__(self, calls, fail_on=None):
        self.calls = calls
        self.fail_on = fail_on

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        if self.fail_on and self.fail_on in query and params.get("props", {}).get("path") == "/boom":
            raise RuntimeError("neo4j says no")
        self.calls.append((query, params))
        return MagicMock()


class _Driver:
    def __init__(self, fail_on=None):
        self.calls = []
        self.fail_on = fail_on

    def session(self):
        return _Session(self.calls, self.fail_on)


class _Harness(RouteExposureMixin):
    def __init__(self, fail_on=None):
        self.driver = _Driver(fail_on)


def _finding(**over):
    base = {
        "endpoint_url": BASE + "/internal/users/export", "baseurl": BASE,
        "path": "/internal/users/export", "http_method": "GET", "source": "route_exposure",
        "exposure_kind": "anonymous_access", "vulnerability_type": "unauthenticated_endpoint",
        "route_class": "data_export", "needs_agent_confirmation": True, "severity": "info",
        "confidence": 0.9, "anon_status": 200, "authed_status": 200, "bodies_match": True,
        "anon_content_class": "json", "anon_size_bucket": "1-10k",
        "auth_expected_by": ["path_word"], "leak_signals": ["pii_others"], "pii_types": ["email"],
        "pii_record_estimate": 25, "sensitive_fields": [], "secret_types": [],
        "generated_by": "found", "variant_of": "", "catch_all_check": "passed", "signature": "",
        "evidence_snippet": "keys: [].id, [].email",
    }
    base.update(over)
    return base


def _write(data, harness=None):
    h = harness or _Harness()
    stats = h.update_graph_from_route_exposure({"route_exposure": data}, "u1", "p1")
    return h.driver.calls, stats


def _vuln_calls(calls):
    return [(q, p) for q, p in calls if "MERGE (v:Vulnerability" in q]


class TestVulnerabilityWrite(unittest.TestCase):
    def test_one_statement_per_finding_with_the_tenant_key(self):
        calls, stats = _write({"findings": [_finding(), _finding(exposure_kind="sensitive_data",
                                                                 vulnerability_type="sensitive_data_exposure")]})
        vulns = _vuln_calls(calls)
        self.assertEqual(len(vulns), 2)
        self.assertEqual(stats["vulnerabilities_created"], 2)
        for query, params in vulns:
            self.assertIn("MERGE (v:Vulnerability {id: $vuln_id, user_id: $user_id, project_id: $project_id})", query)
            self.assertIn("ON CREATE SET v.source = 'route_exposure'", query)
            self.assertEqual((params["user_id"], params["project_id"]), ("u1", "p1"))
            for anchor in ("e:Endpoint", "bu:BaseURL"):
                self.assertRegex(query, rf"OPTIONAL MATCH \({anchor} \{{[^}}]*user_id: \$user_id, project_id: \$project_id\}}\)")

    def test_the_secrets_in_a_response_are_written_beside_their_types(self):
        f = _finding(exposure_kind="secret_in_response", vulnerability_type="exposed_secret",
                     needs_agent_confirmation=False, severity="high",
                     secret_types=["AWS Access Key ID"], secret_values=["AKIAQ7R2M9X4K1T8B3V6"],
                     secret_value_types=["AWS Access Key ID"])
        (_q, params), = _vuln_calls(_write({"findings": [f]})[0])
        self.assertEqual(params["props"]["secret_values"], ["AKIAQ7R2M9X4K1T8B3V6"])
        self.assertEqual(params["props"]["secret_value_types"], ["AWS Access Key ID"])

    def test_props_are_flat_and_carry_the_locators(self):
        (_q, params), = _vuln_calls(_write({"findings": [_finding()]})[0])
        props = params["props"]
        for key, value in props.items():
            self.assertNotIsInstance(value, dict, key)
            if isinstance(value, list):
                self.assertTrue(all(isinstance(v, str) for v in value), key)
        self.assertEqual(props["type"], "unauthenticated_endpoint")
        self.assertEqual(props["matched_at"], BASE + "/internal/users/export")
        self.assertEqual(props["host"], "10.0.0.5")
        self.assertIs(props["is_dast_finding"], False)
        self.assertTrue(props["name"] and props["description"])
        for banned in ("triage_score", "stale_since", "muted", "source"):
            self.assertNotIn(banned, props)

    def test_none_is_dropped_never_written(self):
        (_q, params), = _vuln_calls(_write({"findings": [_finding(authed_status=None, bodies_match=None)]})[0])
        self.assertNotIn("authed_status", params["props"])
        self.assertNotIn("bodies_match", params["props"])

    def test_id_is_identity_only(self):
        """T10: a changing status, signal, class or Jev answer keeps the node."""
        calls_a = _vuln_calls(_write({"findings": [_finding()]})[0])
        calls_b = _vuln_calls(_write({"findings": [_finding(
            anon_status=206, leak_signals=["pii"], route_class="internal_api", confidence=0.4,
            route_jev_kind="internal_api", evidence_snippet="other")]})[0])
        self.assertEqual(calls_a[0][1]["vuln_id"], calls_b[0][1]["vuln_id"])
        other_kind = _vuln_calls(_write({"findings": [_finding(exposure_kind="sensitive_data")]})[0])
        self.assertNotEqual(calls_a[0][1]["vuln_id"], other_kind[0][1]["vuln_id"])
        self.assertEqual(calls_a[0][1]["vuln_id"],
                         _vuln_id("u1", "p1", BASE, "/internal/users/export", "GET", "anonymous_access"))
        self.assertTrue(calls_a[0][1]["vuln_id"].startswith("route_exposure_"))
        self.assertNotEqual(_vuln_id("u1", "p1", BASE, "/x", "GET", "k"),
                            _vuln_id("u2", "p1", BASE, "/x", "GET", "k"))

    def test_jev_opinions_are_cleared_then_set(self):
        (query, params), = _vuln_calls(_write({"findings": [_finding(route_jev_sensitivity=80,
                                                                       route_jev_source="jev_classifier")]})[0])
        self.assertRegex(query, r"REMOVE v\.route_jev_kind, v\.route_jev_kind_confidence, v\.route_jev_sensitivity")
        self.assertIn("SET v += $jev_props", query)
        self.assertLess(query.index("REMOVE v.route_jev_kind"), query.index("SET v += $jev_props"))
        self.assertEqual(params["jev_props"], {"route_jev_sensitivity": 80, "route_jev_source": "jev_classifier"})
        self.assertNotIn("route_jev_sensitivity", params["props"])

    def test_every_jev_field_the_scan_writes_is_persisted_and_cleared(self):
        """Each hook's annotation reaches the node, and a run without Jev clears it."""
        jev = {"route_jev_kind": "data_export", "route_jev_kind_confidence": 90,
               "route_jev_sensitivity": 85, "route_jev_source": "jev_classifier",
               "route_jev_privacy": 87, "anon_page_class": "login_only",
               "anon_page_class_confidence": 88, "anon_page_class_source": "jev_classifier"}
        (query, params), = _vuln_calls(_write({"findings": [_finding(**jev)]})[0])
        self.assertEqual(params["jev_props"], jev)
        removed = query[query.index("REMOVE"):query.index("SET v += $jev_props")]
        for key in jev:
            self.assertIn(f"v.{key}", removed)
            self.assertNotIn(key, params["props"])

    def test_artifacts_attach_to_the_base_url_only(self):
        (_q, params), = _vuln_calls(_write({"findings": [_finding(
            exposure_kind="env_file", vulnerability_type="exposed_env_file", path="/.env",
            needs_agent_confirmation=False, severity="high")]})[0])
        self.assertIs(params["attach_endpoint"], False)
        (_q, params), = _vuln_calls(_write({"findings": [_finding()]})[0])
        self.assertIs(params["attach_endpoint"], True)

    def test_one_bad_finding_never_fails_the_batch(self):
        h = _Harness(fail_on="MERGE (v:Vulnerability")
        calls, stats = _write({"findings": [_finding(path="/boom"), _finding()]}, h)
        self.assertEqual(stats["vulnerabilities_created"], 1)
        self.assertEqual(len(stats["errors"]), 1)
        calls, stats = _write({"findings": [_finding(baseurl="")]})
        self.assertEqual(stats["vulnerabilities_created"], 0)
        self.assertEqual(len(stats["errors"]), 1)


class TestEndpointWrites(unittest.TestCase):
    def test_status_on_existing_routes_is_a_literal_match_set(self):
        """T12: the literal SET keeps anon_status visible to the documentation scan."""
        calls, stats = _write({"endpoint_status": [
            {"baseurl": BASE, "path": "/api/v2/orders/42", "method": "get", "anon_status": 401},
            {"baseurl": BASE, "path": "/x", "anon_status": "401"},          # not an int: skipped
        ]})
        (query, params), = calls
        self.assertIn("MATCH (e:Endpoint {path: r.path, method: r.method, baseurl: r.baseurl,", query)
        self.assertNotIn("MERGE", query)
        self.assertIn("SET e.anon_status = r.anon_status", query)
        self.assertEqual(params["rows"], [{"baseurl": BASE, "path": "/api/v2/orders/42",
                                           "method": "GET", "anon_status": 401}])
        self.assertEqual(stats["endpoint_status_set"], 1)

    def test_new_endpoint_merge_carries_the_declared_only_clear(self):
        """T11: every Endpoint MERGE clears the declared-only flag."""
        calls, stats = _write({"new_endpoints": [
            {"baseurl": BASE, "path": "/api/admin/export", "method": "GET", "category": "admin",
             "anon_status": 200, "generated_by": "seed"}]})
        (query, params), = calls
        self.assertTrue(query.lstrip().startswith("MATCH (bu:BaseURL {url: $baseurl, user_id: $user_id, project_id: $project_id})"))
        self.assertIn("MERGE (e:Endpoint {path: $path, method: 'GET', baseurl: $baseurl,", query)
        self.assertRegex(query, r"SET e\.openapi_declared_only = CASE WHEN coalesce\(e\.openapi_declared_only, "
                                r"e\.openapi_declared, false\) THEN false ELSE e\.openapi_declared_only END")
        self.assertIn("ON CREATE SET e.source = 'route_exposure'", query)
        self.assertIn("e.anon_status = $anon_status", query)
        self.assertIn("MERGE (bu)-[:HAS_ENDPOINT]->(e)", query)
        self.assertEqual((params["generated_by"], params["anon_status"]), ("seed", 200))
        self.assertEqual(stats["endpoints_created"], 1)

    def test_an_artifact_never_becomes_an_endpoint(self):
        calls, stats = _write({"new_endpoints": [
            {"baseurl": BASE, "path": "/.git/HEAD", "anon_status": 200},
            {"baseurl": BASE, "path": "/app/.svn/entries", "anon_status": 200}]})
        self.assertEqual(calls, [])
        self.assertTrue(is_artifact_path("/a/.hg/requires") and not is_artifact_path("/api/hg"))

    def test_empty_input_writes_nothing(self):
        for data in ({}, {"findings": [], "endpoint_status": [], "new_endpoints": []}):
            calls, stats = _write(data)
            self.assertEqual(calls, [])
            self.assertEqual(stats["vulnerabilities_created"], 0)
        h = _Harness()
        self.assertEqual(h.update_graph_from_route_exposure({}, "u", "p")["errors"], [])


class TestUserInputLink(unittest.TestCase):
    def test_links_the_node_each_finding_was_written_to(self):
        h = _Harness()
        findings = [_finding(), _finding(path="/.env", exposure_kind="env_file")]
        self.assertEqual(h.link_route_exposure_user_input("ui-1", findings, "u1", "p1"), 2)
        [(query, params)] = h.driver.calls
        self.assertIn("MERGE (ui)-[:PRODUCED]->(v)", query)
        self.assertIn("{id: $ui_id, user_id: $user_id, project_id: $project_id}", query)
        self.assertIn("{id: vid, user_id: $user_id, project_id: $project_id}", query)
        self.assertEqual(params["ids"], sorted(
            _vuln_id("u1", "p1", BASE, f["path"], "GET", f["exposure_kind"]) for f in findings))

    def test_no_findings_writes_nothing(self):
        h = _Harness()
        self.assertEqual(h.link_route_exposure_user_input("ui-1", [], "u1", "p1"), 0)
        self.assertEqual(h.driver.calls, [])


class TestReachable(unittest.TestCase):
    def test_reachable_from_recon_mixin(self):
        sys.modules.setdefault("neo4j", MagicMock())
        sys.modules.setdefault("dotenv", MagicMock())
        from graph_db.mixins.recon_mixin import ReconMixin
        self.assertTrue(callable(getattr(ReconMixin, "update_graph_from_route_exposure", None)))

    def test_every_finding_field_lands_on_the_node(self):
        """Graph completeness: every §6.1 field the scanner emits is written."""
        from graph_db.mixins.recon import route_exposure_mixin as m
        finding = _finding(cors_variants=["null"], cache_signals=["age"], git_walk_proof="head>ref>commit")
        (_q, params), = _vuln_calls(_write({"findings": [finding]})[0])
        missing = set(finding) - set(params["props"]) - {"endpoint_url", "source"}
        self.assertEqual(missing, set())
        self.assertEqual(params["props"]["matched_at"], finding["endpoint_url"])
        self.assertTrue(set(m._FINDING_PROPS) >= set(finding) - {"endpoint_url", "source"})


if __name__ == "__main__":
    unittest.main()
