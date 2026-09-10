"""The mute invariant at the tenant-scoping chokepoint.

A finding an operator has muted keeps its functional label and gains `:Muted`.
The invariant this file defends is that **no Cypher the agent can emit will ever
return such a node** - not a labelled match, not a bare `MATCH (n)`, not a label
expression, not a query that asks for the `Muted` label by name.

That is deliberately the same class of guarantee as tenant isolation, and it is
enforced in the same place and by the same mechanism: `scope_query` rewrites
EVERY node pattern, and refuses anything it cannot prove it rewrote. So these
tests are the mute half of the leak-regression suite in `test_redagraph.py`, and
they are written the same way - by shape, adversarially, one case per way an LLM
can spell a pattern.

These assert on the Cypher that is generated, not on a live database: the seam
under test is the rewrite, and a Neo4j round trip would only re-test Neo4j.

Run: python -m pytest tests/test_tenant_filter_muted.py
"""

import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.tenant_filter import (  # noqa: E402
    MUTED_LABEL,
    TenantScopeError,
    _iter_node_patterns,
    find_unscoped_node_pattern,
    inject_tenant_filter,
    names_muted_label,
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


def tenant_patterns(cypher):
    """Every node pattern in `cypher` that carries the tenant keys.

    Global reference patterns (`:CVE`) carry no tenant property and are never
    muted, so they are excluded rather than asserted on.
    """
    return [
        cypher[start:end]
        for start, end, inner, parseable in _iter_node_patterns(cypher)
        if parseable and "$tenant_user_id" in inner
    ]


class TestEveryPatternShapeExcludesMuted(unittest.TestCase):
    """The shapes from the cross-tenant leak, re-run for mute.

    A shape that scopes correctly but forgets the mute term is exactly as broken
    as one that forgets the tenant keys: the agent gets back a finding a human
    told it to stop looking at.
    """

    SHAPES = {
        "labelled": "MATCH (v:Vulnerability) RETURN v",
        "unlabelled variable": "MATCH (n) WHERE n:Secret RETURN n",
        "multi label": "MATCH (n:Vulnerability:Nuclei) RETURN n",
        "backtick label": "MATCH (n:`Mal Package`) RETURN n",
        "unlabelled with props": 'MATCH (n {name: "x"}) RETURN n',
        "label without variable": "MATCH (:Secret) RETURN count(*)",
        "anonymous endpoint": "MATCH (v:Vulnerability)-[:FOUND_AT]->() RETURN v",
        "second pattern unlabelled": "MATCH (v:Vulnerability) OPTIONAL MATCH (n) RETURN v, n",
        "label union": "MATCH (n:Secret|MultiscannerFinding) RETURN n",
        "negated label": "MATCH (n:!Package) RETURN n",
        "path pattern": "MATCH (d:Domain)-[:HAS_VULNERABILITY*1..2]->(v:Vulnerability) RETURN v",
        "nested predicate": (
            "MATCH (p:Package) WHERE EXISTS { MATCH (p)-[:FLAGGED_AS]->(m:MalPackageFinding) } "
            "RETURN p"
        ),
    }

    def test_every_tenant_pattern_carries_the_mute_exclusion(self):
        for name, query in self.SHAPES.items():
            with self.subTest(shape=name):
                out = scoped(query)
                patterns = tenant_patterns(out)
                self.assertTrue(patterns, f"{name}: nothing was scoped at all: {out}")
                for pattern in patterns:
                    self.assertIn(
                        f"!{MUTED_LABEL}",
                        pattern,
                        f"{name}: pattern {pattern} can still match a muted node",
                    )

    def test_a_bare_match_cannot_reach_a_muted_node(self):
        # The leak-class case: no label in the pattern, so nothing to attach an
        # exclusion to except the pattern itself.
        self.assertEqual(
            scoped("MATCH (n) RETURN n"),
            "MATCH (n:!Muted {user_id: $tenant_user_id, "
            "project_id: $tenant_project_id}) RETURN n",
        )

    def test_a_union_is_parenthesised_before_the_exclusion(self):
        # `:A|B&!Muted` would parse as `A OR (B AND NOT Muted)` and return a
        # muted A. The union has to be grouped first.
        out = scoped("MATCH (n:Secret|MultiscannerFinding) RETURN n")
        self.assertIn("(n:(Secret|MultiscannerFinding)&!Muted {", out)

    def test_a_legacy_colon_conjunction_is_respelled_not_appended(self):
        # Neo4j 5 refuses to mix ':' conjunction with '&' in one pattern, so
        # `:A:B&!Muted` is a syntax error, not a filter.
        out = scoped("MATCH (n:Vulnerability:Nuclei) RETURN n")
        self.assertIn("(n:Vulnerability&Nuclei&!Muted {", out)
        self.assertNotIn("Vulnerability:Nuclei", out)

    def test_a_backticked_label_is_preserved_verbatim(self):
        out = scoped("MATCH (n:`Mal Package`) RETURN n")
        self.assertIn("(n:`Mal Package`&!Muted {", out)


class TestTheAgentHasNoVocabularyForMute(unittest.TestCase):
    """Hiding muted nodes is not enough if the agent can still ask about them."""

    def test_naming_the_muted_label_is_refused(self):
        for query in (
            "MATCH (n:Muted) RETURN n",
            "MATCH (n) WHERE n:Muted RETURN n",
            "MATCH (v:Vulnerability) WHERE NOT v:Muted RETURN v",
            "MATCH (n:Vulnerability|Muted) RETURN n",
            "MATCH (n) RETURN [l IN labels(n) WHERE l <> Muted] AS kind",
        ):
            with self.subTest(query=query):
                self.assertTrue(refused(query), query)

    def test_the_refusal_does_not_explain_how_to_evade_it(self):
        with self.assertRaises(TenantScopeError) as ctx:
            scoped("MATCH (n:Muted) RETURN n")
        self.assertIn("reserved", str(ctx.exception))

    def test_a_property_called_muted_is_not_the_label(self):
        # Lowercase `muted` is an ordinary property; only the label is reserved.
        out = scoped("MATCH (v:Vulnerability) RETURN v.muted AS m")
        self.assertIn("v.muted", out)

    def test_the_word_inside_a_string_literal_is_not_a_label_reference(self):
        # It cannot leak anything: the pattern that bound `n` already excluded
        # muted nodes, so this is only ever a text comparison.
        self.assertFalse(names_muted_label("MATCH (v:Vulnerability) WHERE v.note = 'Muted'"))
        out = scoped("MATCH (v:Vulnerability) WHERE v.note = 'Muted' RETURN v")
        self.assertIn("'Muted'", out)

    def test_a_comment_naming_the_label_is_ignored(self):
        self.assertFalse(names_muted_label("MATCH (v:Vulnerability) // Muted\nRETURN v"))


class TestInjectionIsIdempotent(unittest.TestCase):
    """`scope_query` re-parses its own output, and callers may re-scope.

    If the rewritten form did not survive a second pass, every query would be
    refused the moment the mute term was added - or worse, gain a second term
    each time it was handled.
    """

    QUERIES = [
        "MATCH (v:Vulnerability) RETURN v",
        "MATCH (n) RETURN n",
        "MATCH (n:Secret|MultiscannerFinding) RETURN n",
        "MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id",
        "MATCH (:Secret) RETURN count(*)",
        "MATCH (n:Vulnerability:Nuclei) RETURN n",
    ]

    def test_scoping_twice_changes_nothing(self):
        for query in self.QUERIES:
            with self.subTest(query=query):
                once = inject_tenant_filter(query, UID, PID)
                twice = inject_tenant_filter(once, UID, PID)
                self.assertEqual(once, twice)

    def test_the_rewritten_form_still_passes_the_backstop(self):
        # The failure this guards: `find_unscoped_node_pattern` runs on the
        # ALREADY-injected query, so a mute term it cannot parse reads as an
        # unscoped pattern and the query is refused.
        for query in self.QUERIES:
            with self.subTest(query=query):
                injected = inject_tenant_filter(query, UID, PID)
                self.assertIsNone(find_unscoped_node_pattern(injected))

    def test_scope_query_is_not_re_entrant_and_says_so_loudly(self):
        """Pinning a sharp edge rather than leaving it to be discovered.

        `scope_query` checks for the reserved label on its RAW input, before it
        adds its own `!Muted` term - so feeding it output it already produced is
        refused. No caller does that today (all three pass fresh LLM- or
        worker-supplied Cypher, and saved data filters store the raw form), and
        the failure is a loud refusal rather than a silent leak, which is the
        direction this module errs in everywhere else.
        """
        once = scoped("MATCH (v:Vulnerability) RETURN v")
        self.assertTrue(refused(once))

    def test_the_exclusion_is_not_duplicated(self):
        once = inject_tenant_filter("MATCH (v:Vulnerability) RETURN v", UID, PID)
        twice = inject_tenant_filter(once, UID, PID)
        self.assertEqual(twice.count(f"!{MUTED_LABEL}"), 1)


class TestMuteDoesNotWeakenTenantIsolation(unittest.TestCase):
    """The mute term rides on the tenant rewrite; it must not displace it."""

    def test_every_shape_still_carries_both_tenant_keys(self):
        for name, query in TestEveryPatternShapeExcludesMuted.SHAPES.items():
            with self.subTest(shape=name):
                out = scoped(query)
                self.assertIsNone(find_unscoped_node_pattern(out))
                for pattern in tenant_patterns(out):
                    self.assertIn("user_id: $tenant_user_id", pattern)
                    self.assertIn("project_id: $tenant_project_id", pattern)

    def test_a_reference_label_gets_neither_tenant_keys_nor_a_mute_term(self):
        # CVE/MitreData/Capec are the global catalogue: no tenant property to
        # filter on, and nothing there is ever muted.
        out = scoped("MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN c.id")
        self.assertIn("(c:CVE)", out)

    def test_an_unanchored_reference_query_is_still_refused(self):
        self.assertTrue(refused("MATCH (c:CVE) RETURN c.id"))


class TestMalformedLabelExpressionsFailClosed(unittest.TestCase):
    """Reading the full label grammar must not mean accepting nonsense.

    The rewrite completes a label expression, so a half-written one must be
    refused rather than completed: `(n:)` silently becoming `(n:!Muted {tenant})`
    would turn a query Neo4j rejects into one that returns the whole project.
    """

    MALFORMED = [
        "MATCH (n:) RETURN n",
        "MATCH (n:A&) RETURN n",
        "MATCH (n:&A) RETURN n",
        "MATCH (n:A::B) RETURN n",
        "MATCH (n:A|) RETURN n",
        "MATCH (n:!) RETURN n",
        "MATCH (n:(A|B) RETURN n",
        "MATCH (n:A)) RETURN n",
    ]

    def test_a_malformed_label_expression_is_refused(self):
        for query in self.MALFORMED:
            with self.subTest(query=query):
                self.assertTrue(refused(query), query)


if __name__ == "__main__":
    unittest.main()
