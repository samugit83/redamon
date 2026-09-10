"""The global-reference-label exemption in the tenant filter.

CVE, MitreData and Capec are the public NVD/MITRE catalogue: UNIQUE on their
natural id, one node per CVE for the whole database, carrying no tenant
property. Injecting a tenant filter on them matches nothing, so the agent went
blind to every CVE once the writers stopped stamping them.

The exemption is a hole in the isolation backstop, so these tests are mostly
about what must NOT be exempt. Anything that regresses here reads across
tenants.

Run: python -m unittest tests.test_tenant_filter_reference_labels
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.tenant_filter import (  # noqa: E402
    GLOBAL_REFERENCE_LABELS,
    TenantScopeError,
    find_unscoped_node_pattern,
    inject_tenant_filter,
    scope_query,
)

UID, PID = "u1", "p1"


def scoped(cypher):
    return scope_query(cypher, UID, PID)


def refused(cypher):
    try:
        scope_query(cypher, UID, PID)
        return False
    except TenantScopeError:
        return True


class TestReferenceLabelsAreReachable(unittest.TestCase):
    def test_the_catalogue_is_exactly_three_labels(self):
        self.assertEqual(set(GLOBAL_REFERENCE_LABELS), {"CVE", "MitreData", "Capec"})

    def test_a_traversal_from_tenant_data_reaches_the_cve(self):
        out = scoped("MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id")
        self.assertIn("(t:Technology&!Muted {user_id: $tenant_user_id", out)
        # The whole point: no filter lands on the CVE, because it has no tenant
        # property to filter on.
        self.assertIn("(c:CVE)", out)

    def test_the_full_cve_cwe_capec_chain_survives(self):
        out = scoped(
            "MATCH (d:Domain)-[:HAS_VULNERABILITY]->(v:Vulnerability)-[:HAS_CVE]->(c:CVE)"
            "-[:HAS_CWE]->(m:MitreData)-[:HAS_CAPEC]->(k:Capec) RETURN k.name"
        )
        for untouched in ("(c:CVE)", "(m:MitreData)", "(k:Capec)"):
            self.assertIn(untouched, out)
        for filtered in ("(d:Domain&!Muted {", "(v:Vulnerability&!Muted {"):
            self.assertIn(filtered, out)

    def test_a_reference_pattern_with_its_own_props_is_left_alone(self):
        out = scoped("MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE {id: 'CVE-2021-1'}) RETURN c")
        self.assertIn("(c:CVE {id: 'CVE-2021-1'})", out)


class TestTheExemptionIsNotAHole(unittest.TestCase):
    def test_a_reference_query_with_no_tenant_anchor_is_refused(self):
        # Which CVEs exist in the database is a weak signal about what other
        # tenants have scanned, so reference nodes are readable only from a
        # query already anchored to the caller's own data.
        self.assertTrue(refused("MATCH (c:CVE) RETURN c.id"))
        self.assertTrue(refused("MATCH (m:MitreData) RETURN m"))
        self.assertTrue(refused("MATCH (k:Capec) RETURN k"))
        self.assertTrue(refused("MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN c, m"))

    def test_a_negated_label_is_never_exempt(self):
        # `(n:!CVE)` is every node that is NOT a CVE. Exempting it would hand
        # back the entire database, so it must be scoped like any other pattern.
        # (It used to be REFUSED, because the pattern regex could not read a
        # negated label at all. Mute injection made that regex read the full
        # label-expression grammar, so the shape now parses - and being scoped is
        # the property that was ever load-bearing here, not being rejected.)
        for query in ("MATCH (n:!CVE) RETURN n", "MATCH (d:Domain), (n:!CVE) RETURN n"):
            with self.subTest(query=query):
                out = scoped(query)
                self.assertIn("(n:!CVE&!Muted {user_id: $tenant_user_id", out)
                self.assertIsNone(find_unscoped_node_pattern(out))

    def test_a_label_union_is_never_exempt(self):
        # `(n:CVE|Domain)` matches Domains too.
        out = scoped("MATCH (n:CVE|Domain) RETURN n")
        self.assertIn("$tenant_user_id", out)

    def test_a_mixed_label_conjunction_is_never_exempt(self):
        out = scoped("MATCH (n:CVE:Domain) RETURN n")
        self.assertIn("$tenant_user_id", out)

    def test_an_unlabelled_pattern_is_never_exempt(self):
        out = scoped("MATCH (n) RETURN n")
        self.assertIn("$tenant_user_id", out)
        out = scoped("MATCH (d:Domain)-[:X]->() RETURN d")
        self.assertIn("$tenant_user_id", out)

    def test_a_backticked_reference_label_is_not_exempt(self):
        # A backticked label may contain ':', which would break the label split.
        # Refusing to exempt it is the conservative direction: worst case the
        # query is scoped and returns nothing, rather than running unscoped.
        out = inject_tenant_filter("MATCH (d:Domain)-[:X]->(c:`CVE`) RETURN c", UID, PID)
        self.assertIn("$tenant_user_id", out.split("->")[1])

    def test_a_label_tested_in_the_where_clause_is_not_exempt(self):
        # The classic bypass: no label in the pattern, label asserted later.
        out = scoped("MATCH (d:Domain), (n) WHERE n:CVE RETURN n")
        self.assertIn("(n:!Muted {user_id: $tenant_user_id", out)

    def test_every_non_reference_label_still_gets_scoped(self):
        for label in ("Domain", "Package", "GithubSecret", "MultiscannerFinding",
                      "Vulnerability", "Technology", "ChainFinding", "Secret"):
            out = scoped(f"MATCH (n:{label}) RETURN n")
            self.assertIn("$tenant_user_id", out, label)
            self.assertIn("$tenant_project_id", out, label)


class TestBackstopAgreesWithInjection(unittest.TestCase):
    """`find_unscoped_node_pattern` runs on the INJECTED query and must accept
    exactly what injection chose to leave alone, or every CVE query 500s."""

    def test_an_injected_anchored_query_passes_the_backstop(self):
        injected = inject_tenant_filter(
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c", UID, PID)
        self.assertIsNone(find_unscoped_node_pattern(injected))

    def test_an_injected_unanchored_reference_query_fails_the_backstop(self):
        injected = inject_tenant_filter("MATCH (c:CVE) RETURN c", UID, PID)
        self.assertIsNotNone(find_unscoped_node_pattern(injected))


if __name__ == "__main__":
    unittest.main()
