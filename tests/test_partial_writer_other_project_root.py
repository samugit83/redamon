"""A partial run on one root never makes another project root's host an ExternalDomain (S-10).

A Domain-batch project with roots a.example.test and b.example.test. The full
pipeline carries every root in "all_project_roots", so a host under the other
root attaches to it. A partial run carries only its own roots in "domains"
(partial_recon_modules/osint_enrichment.py run_urlscan builds exactly that
dict) while partial_recon._prepare_scope records every project group through
set_run_scope_groups. attach_roots ignored those groups, so classify_host found
no root for www.b.example.test and the urlscan discovery writer MERGEd it as an
ExternalDomain of the project.

A fake session records the Cypher; no graph. Names are example.test only.
"""
from __future__ import annotations

import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

for _p in ("/repo", str(Path(__file__).resolve().parents[1])):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from graph_db.mixins.recon import scope  # noqa: E402

ROOT_A, ROOT_B = "a.example.test", "b.example.test"
GROUPS = [
    {"scan_root": ROOT_A, "org_domain": ROOT_A, "mode": "subdomains",
     "include_root": True, "exact_hosts": []},
    {"scan_root": ROOT_B, "org_domain": ROOT_B, "mode": "subdomains",
     "include_root": True, "exact_hosts": []},
]


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        result = MagicMock()
        result.single.return_value = {"n": 1}
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _entry(host: str, in_scope: bool) -> dict:
    return {"domain": host, "in_scope": in_scope, "ip": "", "ip_in_scope": False,
            "url": f"https://{host}/", "scan_time": "2026-10-01T00:00:00Z"}


def _partial_run_dict(entries) -> dict:
    # The dict partial run_urlscan's _one_root hands the writers.
    return {"domain": ROOT_A, "domains": [ROOT_A],
            "urlscan": {"results_count": len(entries), "entries": entries,
                        "urls_with_paths": []}}


def _external_domains(writer) -> set:
    return {p.get("ed_domain") for q, p in writer.session.calls if "ExternalDomain" in q}


class PartialRunOnOneRootOfABatch(unittest.TestCase):
    def setUp(self):
        scope.set_run_scope_groups(GROUPS)  # what partial_recon._prepare_scope does

    def tearDown(self):
        scope.set_run_scope_groups([])

    def test_the_other_roots_host_is_not_an_external_domain(self):
        for in_scope in (True, False):
            with self.subTest(in_scope=in_scope):
                w = _Writer()
                w.update_graph_from_urlscan_discovery(
                    _partial_run_dict([_entry(f"www.{ROOT_B}", in_scope)]), "u1", "p1")
                self.assertNotIn(f"www.{ROOT_B}", _external_domains(w),
                                 "a project root's host was written as an ExternalDomain")

    def test_scope_helpers_know_the_project_root(self):
        kind, org = scope.attach_for_host(f"www.{ROOT_B}", _partial_run_dict([]))
        self.assertEqual((kind, org), (scope.IN_SCOPE, ROOT_B))

    def test_control_a_third_party_host_is_still_external(self):
        w = _Writer()
        w.update_graph_from_urlscan_discovery(
            _partial_run_dict([_entry("cdn.other-vendor.test", False)]), "u1", "p1")
        self.assertIn("cdn.other-vendor.test", _external_domains(w))

    def test_control_the_full_pipeline_dict_attaches_it(self):
        recon = dict(_partial_run_dict([]), all_project_roots=[ROOT_A, ROOT_B])
        self.assertEqual(scope.attach_for_host(f"www.{ROOT_B}", recon), (scope.IN_SCOPE, ROOT_B))

    def test_the_runs_own_roots_come_first(self):
        # A writer reads roots[0] for an IP-mode host and for a host under no root.
        scope.set_run_scope_groups(list(reversed(GROUPS)))
        self.assertEqual(scope.attach_roots({"domain": ROOT_B, "domains": [ROOT_B]}), [ROOT_B, ROOT_A])
        self.assertEqual(scope.attach_roots({"domain": ROOT_A}), [ROOT_A, ROOT_B])

    def test_a_root_is_listed_once_whatever_its_spelling(self):
        recon = {"domain": ROOT_A, "domains": [ROOT_A.upper() + "."]}
        self.assertEqual(scope.attach_roots(recon), [ROOT_A.upper() + ".", ROOT_B])

    def test_the_writers_dict_is_not_widened(self):
        recon = _partial_run_dict([])
        scope.attach_roots(recon)
        self.assertEqual(recon["domains"], [ROOT_A])

    def test_all_project_roots_still_wins(self):
        recon = dict(_partial_run_dict([]), all_project_roots=[ROOT_A])
        self.assertEqual(scope.attach_roots(recon), [ROOT_A])

    def test_project_orgs_name_every_group(self):
        self.assertEqual(scope.project_orgs(_partial_run_dict([])), [ROOT_A, ROOT_B])


class WithoutTheRunsGroups(unittest.TestCase):
    """The full pipeline, a single-domain project and a legacy recon file never
    set the run's groups: their roots are the run's own scan scope, as before."""

    def setUp(self):
        scope.set_run_scope_groups([])

    def test_the_runs_own_scan_scope(self):
        self.assertEqual(scope.attach_roots(_partial_run_dict([])), [ROOT_A])
        self.assertEqual(scope.attach_roots({"domain": ROOT_A}), [ROOT_A])
        self.assertEqual(scope.attach_roots({}), [])

    def test_a_host_under_an_unknown_root_stays_external(self):
        kind, org = scope.attach_for_host(f"www.{ROOT_B}", _partial_run_dict([]))
        self.assertEqual((kind, org), (scope.OUT_OF_SCOPE, None))


if __name__ == "__main__":
    unittest.main()
