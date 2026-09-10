"""
Strategy row 3: partial recon must not pick an arbitrary domain.

get_graph_inputs_for_tool backed the partial-recon input modal. Its
SubdomainDiscovery query was `OPTIONAL MATCH (d:Domain {user_id, project_id})`
followed by `result.single()`, which assumes a project has exactly ONE Domain
node. A Domain-batch project has one per group, so the modal silently offered
whichever row Neo4j returned first and the re-run scanned a domain the operator
never selected.

The method now returns every domain in `domains`, and populates the singular
`domain` only when there is exactly one, so a caller that cannot present a choice
fails closed instead of guessing.

Run with:
    python3 -m pytest tests/test_graph_inputs_multi_domain.py -v
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.user_input_mixin import UserInputMixin  # noqa: E402


class _Client(UserInputMixin):
    """The mixin with a scripted Neo4j session."""

    def __init__(self, rows):
        self._rows = rows
        session = MagicMock()
        session.run.return_value = iter(rows)
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        self.driver = MagicMock()
        self.driver.session.return_value = session
        self.session = session

    @property
    def cypher(self):
        return self.session.run.call_args[0][0]


def _row(domain, count):
    return {"domain": domain, "subdomain_count": count}


class TestSubdomainDiscoveryInputs(unittest.TestCase):
    def test_several_domains_are_all_returned(self):
        c = _Client([_row("domain1.com", 3), _row("domain2.it", 1)])
        out = c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertEqual(out["domains"], ["domain1.com", "domain2.it"])

    def test_the_singular_domain_is_null_when_the_choice_is_ambiguous(self):
        # THE regression: this used to be whichever row came back first, and the
        # caller scanned it without the operator ever choosing.
        c = _Client([_row("domain1.com", 3), _row("domain2.it", 1)])
        out = c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertIsNone(out["domain"])

    def test_a_single_domain_project_still_gets_its_domain(self):
        c = _Client([_row("only.com", 7)])
        out = c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertEqual(out["domain"], "only.com")
        self.assertEqual(out["domains"], ["only.com"])
        self.assertEqual(out["existing_subdomains_count"], 7)
        self.assertEqual(out["source"], "graph")

    def test_subdomain_counts_are_summed_across_domains(self):
        c = _Client([_row("a.com", 2), _row("b.com", 5)])
        out = c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertEqual(out["existing_subdomains_count"], 7)

    def test_an_empty_graph_falls_back_to_settings(self):
        c = _Client([])
        out = c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertIsNone(out["domain"])
        self.assertEqual(out["domains"], [])
        self.assertEqual(out["source"], "settings")

    def test_rows_with_a_null_domain_are_dropped(self):
        c = _Client([_row(None, 0), _row("real.com", 1)])
        out = c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertEqual(out["domains"], ["real.com"])
        self.assertEqual(out["domain"], "real.com")

    def test_the_query_is_still_tenant_scoped(self):
        # Both keys must stay in the MATCH or one project would read another's
        # domains through this endpoint.
        c = _Client([_row("a.com", 1)])
        c.get_graph_inputs_for_tool("SubdomainDiscovery", "u1", "p1")
        self.assertIn("user_id: $uid", c.cypher)
        self.assertIn("project_id: $pid", c.cypher)
        self.assertEqual(c.session.run.call_args[1], {"uid": "u1", "pid": "p1"})


if __name__ == "__main__":
    unittest.main()
