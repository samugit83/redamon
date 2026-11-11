"""Unit tests for the normalizer linking logic (session mocked, no Neo4j).

Covers the dispatch between tier-1 (link to an existing Endpoint) and tier-2
(materialise a custom target node chain), the host-anchor branch (hostname vs
raw IP), and the pure helpers. The live-DB behaviour is covered separately by
test_integration_graph.py.
"""
import unittest
from unittest.mock import MagicMock

from normalizer import Finding, write_finding, _is_ip


def _finding(base="http://h:8000", path="/c"):
    return Finding(source="garak", chip="prompt-injection", name="n",
                   baseurl=base, path=path, ai_owasp_llm_id="LLM01",
                   ai_payload_class="garak-x")


def _session(linked: bool, domain=None, apex=False) -> MagicMock:
    """A mock session whose tier-1 query reports e IS NOT NULL = `linked`, and
    whose Domain lookup finds `domain` (None: the host is under no Domain)."""
    s = MagicMock()

    def run(query, **_):
        result = MagicMock()
        if "RETURN e IS NOT NULL AS linked" in query:
            result.single.return_value = {"linked": linked}
        elif "RETURN d.name AS domain" in query:
            result.single.return_value = (
                None if domain is None else {"domain": domain, "apex": apex})
        else:
            result.single.return_value = None
        return result

    s.run.side_effect = run
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



class TestWriteFindingDispatch(unittest.TestCase):
    def test_existing_endpoint_returns_existing_and_skips_creation(self):
        s = _session(linked=True)
        status = write_finding(s, _finding(), "u", "p")
        self.assertEqual(status, "existing")
        # exactly 2 queries: Vulnerability MERGE + tier-1 link. No materialisation.
        self.assertEqual(s.run.call_count, 2)
        self.assertNotIn("ai_attack_target", _all_cypher(s))

    def test_missing_endpoint_materialises_and_returns_created(self):
        s = _session(linked=False, domain="h")
        status = write_finding(s, _finding(), "u", "p")
        self.assertEqual(status, "created")
        # Vuln MERGE + tier-1 + BaseURL/Endpoint create + Domain lookup + anchor = 5.
        self.assertEqual(s.run.call_count, 5)
        cy = _all_cypher(s)
        self.assertIn("ai_attack_target", cy)
        self.assertIn(":Endpoint", cy)
        self.assertIn(":BaseURL", cy)
        self.assertIn(":HAS_ENDPOINT", cy)
        self.assertIn(":HAS_VULNERABILITY", cy)

    def test_hostname_anchors_under_the_domain_recon_wrote(self):
        s = _session(linked=False, domain="example.com")
        write_finding(s, _finding(base="http://api.example.com"), "u", "p")
        cy = _all_cypher(s)
        self.assertIn(":Subdomain", cy)
        self.assertIn(":HAS_BASE_URL", cy)
        self.assertIn(":HAS_SUBDOMAIN", cy)
        self.assertNotIn("MERGE (ip:IP", cy)
        anchor = next(c for c in s.run.call_args_list if "HAS_SUBDOMAIN" in c.args[0])
        self.assertEqual(anchor.kwargs["domain"], "example.com")
        self.assertIn("MATCH (d:Domain {name: $domain", anchor.args[0])

    def test_ip_mode_a_scanned_hostname_attaches_to_its_subdomain_under_its_org(self):
        # P4 (design §6.1): a hostname an IP-mode run scanned is a Subdomain
        # under an org Domain marked ip_hostname_org, which has no ip_mode, so
        # the lookup finds it (the synthetic ip-targets root, ip_mode true, is
        # skipped) and the finding's BaseURL hangs off the existing Subdomain
        # (MERGE on the tenant key matches it). No normalizer change.
        s = _session(linked=False, domain="example.com")
        write_finding(s, _finding(base="https://app.example.com"), "u", "p")
        lookup = next(c for c in s.run.call_args_list if "RETURN d.name AS domain" in c.args[0])
        self.assertIn("coalesce(d.ip_mode, false) = false", lookup.args[0])
        anchor = next(c for c in s.run.call_args_list if "HAS_SUBDOMAIN" in c.args[0])
        self.assertIn("MERGE (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})", anchor.args[0])
        self.assertEqual((anchor.kwargs["host"], anchor.kwargs["domain"]), ("app.example.com", "example.com"))

    def test_a_domain_is_never_merged(self):
        # A guessed "registrable" Domain (co.uk for x.acme.co.uk) is one the
        # scope never named, and blocks partial recon (GDB-12).
        for kwargs in ({"domain": "acme.co.uk"}, {"domain": None},
                       {"domain": "api.example.com", "apex": True}):
            s = _session(linked=False, **kwargs)
            write_finding(s, _finding(base="http://api.example.com"), "u", "p")
            self.assertNotRegex(_all_cypher(s), r"MERGE\s*\(\s*\w*\s*:\s*Domain\b")

    def test_the_domain_lookup_is_label_bounded_and_longest_first(self):
        s = _session(linked=False, domain="example.com")
        write_finding(s, _finding(base="http://API.Example.com"), "u", "p")
        lookup = next(c for c in s.run.call_args_list if "RETURN d.name AS domain" in c.args[0])
        self.assertIn("$host = n OR $host ENDS WITH '.' + n", lookup.args[0])
        self.assertIn("ORDER BY size(n) DESC LIMIT 1", lookup.args[0])
        self.assertIn("coalesce(d.ip_mode, false) = false", lookup.args[0])
        self.assertEqual(lookup.kwargs["host"], "api.example.com")
        self.assertEqual((lookup.kwargs["uid"], lookup.kwargs["pid"]), ("u", "p"))

    def test_a_host_under_no_domain_is_an_external_domain(self):
        s = _session(linked=False, domain=None)
        write_finding(s, _finding(base="http://custom.example.org"), "u", "p")
        cy = _all_cypher(s)
        self.assertIn("MERGE (ed:ExternalDomain {domain: $host, user_id: $uid, project_id: $pid})", cy)
        self.assertNotIn("MERGE (s:Subdomain", cy)

    def test_a_host_equal_to_a_domain_links_only_an_existing_subdomain(self):
        # The scan root is a target only with Include Root, and then recon
        # wrote its Subdomain; nothing is created for it here.
        s = _session(linked=False, domain="example.com", apex=True)
        write_finding(s, _finding(base="http://example.com"), "u", "p")
        anchor = next(c for c in s.run.call_args_list if "HAS_BASE_URL" in c.args[0])
        self.assertIn("MATCH (s:Subdomain {name: $host", anchor.args[0])
        self.assertNotIn("MERGE (s:Subdomain", _all_cypher(s))

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
