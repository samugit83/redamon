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


class TestTheAnchorIsTheSamePath(unittest.TestCase):
    """A reference node is reachable only through a scoped node of its own path.

    The anchor used to be a shape test: one scoped pattern ANYWHERE in the query
    exempted every reference pattern, so `MATCH (a:Domain) WITH count(a) AS c
    MATCH (x:CVE) RETURN x` listed every CVE in the database (the union of what
    every tenant has scanned) even for a project with no Domain at all. Now the
    reference node must be joined to a tenant-scoped node by relationship
    patterns, as the webapp's saved-view filter reads it.
    """

    UNANCHORED = (
        "MATCH (a:Domain) WITH count(a) AS c MATCH (x:CVE) RETURN x",
        "MATCH (a:Domain) WITH a MATCH (c:CVE) RETURN c",
        "MATCH (a:Domain), (c:CVE) RETURN c",
        "MATCH (a:Domain) MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN m",
        "MATCH (t:Technology) OPTIONAL MATCH (c:CVE) RETURN c.id",
        "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) MATCH (k:Capec) RETURN k",
        "MATCH (t:Technology)-[:USES]->(x), (c:CVE) RETURN c",
        "MATCH (t:Technology) RETURN COUNT { (c:CVE) } AS every_cve",
        "MATCH (t:Technology) WHERE EXISTS { (c:CVE) } RETURN t",
        "MATCH (v:Vulnerability) RETURN v.id AS id UNION ALL MATCH (c:CVE) RETURN c.id AS id",
        "MATCH (t:Technology) RETURN [(c:CVE)-[:HAS_CWE]->(m:MitreData) | m.name] AS cwes",
    )

    ANCHORED = (
        "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c",
        "MATCH (c:CVE)<-[:HAS_KNOWN_CVE]-(t:Technology) RETURN c",
        "MATCH (t:Technology)-->(c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN m",
        "MATCH (t:Technology) WHERE EXISTS { (t)-[:HAS_KNOWN_CVE]->(c:CVE) } RETURN t",
        "MATCH (t:Technology) RETURN [(t)- - >(c:CVE) | c.id] AS cves",
        "MATCH (t:Technology) OPTIONAL MATCH (t)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id",
        "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) WHERE id(c) = 1234 RETURN DISTINCT c",
        "MATCH (t:Technology)-/* via */[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id",
        "MATCH (t:Technology)-[r:HAS_KNOWN_CVE {note: ']-, ('}]->(c:CVE) RETURN c.id",
        "MATCH (t:Technology)-[r:HAS_KNOWN_CVE {tags: [1, [2]]}]->(c:CVE) RETURN c.id",
        "MATCH (t:Technology)<-->(c:CVE) RETURN c.id",
        "MATCH (ip:IP) OPTIONAL MATCH (ip)-[:HAS_VULNERABILITY]->(v:Vulnerability)"
        "-[:HAS_CVE]->(cve:CVE) RETURN cve.id",
    )

    def test_a_scoped_node_elsewhere_in_the_query_is_no_anchor(self):
        for query in self.UNANCHORED:
            with self.subTest(query=query):
                self.assertTrue(refused(query), query)

    def test_a_traversal_from_the_projects_own_node_is_still_read(self):
        for query in self.ANCHORED:
            with self.subTest(query=query):
                out = scoped(query)
                self.assertRegex(out, r"\((c|cve):CVE[ )]")
                self.assertIsNone(find_unscoped_node_pattern(out))

    def test_the_refusal_says_how_to_reach_a_reference_node(self):
        with self.assertRaises(TenantScopeError) as ctx:
            scoped("MATCH (a:Domain), (c:CVE) RETURN c")
        message = str(ctx.exception)
        self.assertIn("(c:CVE)", message)
        self.assertIn("relationship", message)
        self.assertIn("(t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)", message)

    def test_the_backstop_alone_wants_the_same_path(self):
        # Run on already-injected Cypher, as scope_query does.
        self.assertIsNotNone(find_unscoped_node_pattern(inject_tenant_filter(
            "MATCH (a:Domain) WITH count(a) AS c MATCH (x:CVE) RETURN x", UID, PID)))
        self.assertIsNone(find_unscoped_node_pattern(inject_tenant_filter(
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c", UID, PID)))

    def test_a_variable_length_hop_is_no_anchor_even_to_the_backstop_alone(self):
        # scope_query refuses `[*]` before this; the backstop must not rely on it.
        injected = inject_tenant_filter("MATCH (t:Technology)-[*]-(c:CVE) RETURN c", UID, PID)
        self.assertIsNotNone(find_unscoped_node_pattern(injected))

    def test_a_reference_node_anchored_only_by_another_reference_node_is_refused(self):
        self.assertTrue(refused("MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN m"))
        self.assertTrue(refused(
            "MATCH (t:Technology) WITH t MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData)"
            "-[:HAS_CAPEC]->(k:Capec) RETURN k"))

    def test_a_variable_bound_by_an_anchored_path_stays_anchored_in_a_later_match(self):
        # The MCP exploit_paths query and the agent prompt's "labelled OPTIONAL
        # MATCH for a CVE neighbour" both re-match the CVE the first path bound.
        for query in (
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) "
            "OPTIONAL MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN c.id, m.cwe_id",
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) WHERE c.id STARTS WITH 'CVE-' "
            "OPTIONAL MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) "
            "OPTIONAL MATCH (m:MitreData)-[:HAS_CAPEC]->(k:Capec) RETURN k.name",
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(`c`:CVE) "
            "OPTIONAL MATCH (m:MitreData)<-[:HAS_CWE]-(c:CVE) RETURN m",
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) "
            "WHERE size([(c:CVE)-[:HAS_CWE]->(m:MitreData) | m]) > 0 RETURN t",
        ):
            with self.subTest(query=query):
                self.assertIsNone(find_unscoped_node_pattern(scoped(query)))

    def test_a_rebinding_across_a_scope_boundary_is_a_fresh_node(self):
        for query in (
            # WITH drops c, so the second (c:CVE) is every CVE in the database.
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) WITH count(c) AS n "
            "MATCH (c:CVE) RETURN c.id",
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) WITH t, c MATCH (c:CVE) RETURN c.id",
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id AS id "
            "UNION MATCH (c:CVE) RETURN c.id AS id",
            "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) "
            "CALL { MATCH (c:CVE) RETURN c AS x } RETURN x.id",
            # bound only inside a comprehension or a subquery, so local to it
            "MATCH (t:Technology) WITH t, [(t)-->(c:CVE) | c] AS l MATCH (c:CVE) RETURN c.id",
            "MATCH (t:Technology) WHERE EXISTS { (t)-->(c:CVE) } MATCH (c:CVE) RETURN c.id",
            "MATCH (t:Technology) WHERE size([(t)-->(c:CVE) | c]) > 0 MATCH (c:CVE) RETURN c.id",
        ):
            with self.subTest(query=query):
                self.assertTrue(refused(query), query)

    def test_a_reference_label_with_tenant_keys_of_its_own_is_never_exempt(self):
        self.assertTrue(refused(
            "MATCH (t:Technology)-->(c:CVE {user_id: 'victim', project_id: 'victim'}) RETURN c"))


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
