"""Unit tests for the normalizer linking logic (session mocked, no Neo4j).

Covers the dispatch between tier-1 (link to an existing Endpoint) and tier-2
(materialise a custom target node chain), the host-anchor branch (hostname vs
raw IP), and the pure helpers. The live-DB behaviour is covered separately by
test_integration_graph.py.
"""
import unittest
from unittest.mock import MagicMock

from normalizer import Finding, write_finding, _is_ip, _registrable


def _finding(base="http://h:8000", path="/c"):
    return Finding(source="garak", chip="prompt-injection", name="n",
                   baseurl=base, path=path, ai_owasp_llm_id="LLM01",
                   ai_payload_class="garak-x")


def _session(linked: bool) -> MagicMock:
    """A mock session whose tier-1 query reports e IS NOT NULL = `linked`."""
    s = MagicMock()
    result = MagicMock()
    result.single.return_value = {"linked": linked}
    s.run.return_value = result
    return s


def _all_cypher(session) -> str:
    return "\n".join(c.args[0] for c in session.run.call_args_list)


class TestPureHelpers(unittest.TestCase):
    def test_is_ip(self):
        self.assertTrue(_is_ip("172.25.0.1"))
        self.assertTrue(_is_ip("10.0.0.255"))
        self.assertTrue(_is_ip("::1"))
        self.assertFalse(_is_ip("example.com"))
        self.assertFalse(_is_ip("api.example.com"))
        self.assertFalse(_is_ip(""))

    def test_registrable(self):
        self.assertEqual(_registrable("api.example.com"), "example.com")
        self.assertEqual(_registrable("a.b.c.example.com"), "example.com")
        self.assertEqual(_registrable("example.com"), "example.com")
        self.assertEqual(_registrable("localhost"), "localhost")


class TestWriteFindingDispatch(unittest.TestCase):
    def test_existing_endpoint_returns_existing_and_skips_creation(self):
        s = _session(linked=True)
        status = write_finding(s, _finding(), "u", "p")
        self.assertEqual(status, "existing")
        # exactly 2 queries: Vulnerability MERGE + tier-1 link. No materialisation.
        self.assertEqual(s.run.call_count, 2)
        self.assertNotIn("ai_attack_target", _all_cypher(s))

    def test_missing_endpoint_materialises_and_returns_created(self):
        s = _session(linked=False)
        status = write_finding(s, _finding(), "u", "p")
        self.assertEqual(status, "created")
        # Vuln MERGE + tier-1 + BaseURL/Endpoint create + hostname anchor = 4.
        self.assertEqual(s.run.call_count, 4)
        cy = _all_cypher(s)
        self.assertIn("ai_attack_target", cy)
        self.assertIn(":Endpoint", cy)
        self.assertIn(":BaseURL", cy)
        self.assertIn(":HAS_ENDPOINT", cy)
        self.assertIn(":HAS_VULNERABILITY", cy)

    def test_hostname_anchors_via_subdomain_and_domain(self):
        s = _session(linked=False)
        write_finding(s, _finding(base="http://api.example.com"), "u", "p")
        cy = _all_cypher(s)
        self.assertIn(":Subdomain", cy)
        self.assertIn(":HAS_BASE_URL", cy)
        self.assertIn(":HAS_SUBDOMAIN", cy)
        self.assertNotIn("MERGE (ip:IP", cy)

    def test_ip_host_anchors_via_ip_node(self):
        s = _session(linked=False)
        write_finding(s, _finding(base="http://172.25.0.1:11435"), "u", "p")
        cy = _all_cypher(s)
        self.assertIn("MERGE (ip:IP", cy)
        self.assertNotIn(":Subdomain", cy)   # IP targets don't fabricate a subdomain

    def test_target_method_and_iface_passed_into_created_endpoint(self):
        s = _session(linked=False)
        target = MagicMock(method="PUT", ai_interface_type="llm-chat", ai_model_ids=["qwen"])
        write_finding(s, _finding(), "u", "p", target=target)
        # find the BaseURL/Endpoint creation call and assert its params
        create = next(c for c in s.run.call_args_list if ":HAS_ENDPOINT" in c.args[0]
                      and "MERGE (e:Endpoint" in c.args[0])
        self.assertEqual(create.kwargs["method"], "PUT")
        self.assertEqual(create.kwargs["iface"], "llm-chat")
        self.assertEqual(create.kwargs["models"], ["qwen"])

    def test_no_target_defaults_method_post(self):
        s = _session(linked=False)
        write_finding(s, _finding(), "u", "p", target=None)
        create = next(c for c in s.run.call_args_list if "MERGE (e:Endpoint" in c.args[0])
        self.assertEqual(create.kwargs["method"], "POST")


if __name__ == "__main__":
    unittest.main(verbosity=2)
