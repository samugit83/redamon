"""REGRESSION: a CALLed procedure carried its query past tenant scoping.

Found by an adversarial review of the inbound MCP server and CONFIRMED live
against the running stack before the fix: a request asserting a tenant that
matches nothing read 5085 nodes belonging to a different user.

    OPTIONAL MATCH (d:Domain) WITH d LIMIT 1
    CALL apoc.cypher.run("MATCH (n) WHERE n.user_id IS NOT NULL
                          RETURN DISTINCT n.user_id", {}) YIELD value
    RETURN value

Why every existing guard approved it:

  * tenant injection rewrites NODE PATTERNS. The inner query is a STRING
    LITERAL, so `code_positions()` correctly marks it non-code and
    `_iter_node_patterns` never sees it.
  * `has_labelled_node_pattern` is satisfied by the outer `OPTIONAL MATCH`,
    which exists only to supply an anchor row so the CALL fires.
  * `find_unscoped_node_pattern` finds nothing to complain about, because after
    injection every pattern it CAN see is scoped.

The same shape via `apoc.cypher.runMany` is a cross-tenant WRITE, and
`\\u0043REATE` inside the literal hides the keyword from `_WRITE_CLAUSE_RE`,
which scans raw text. `apoc.load.json` points the hole outward as an SSRF from
inside the database container. APOC ships enabled and unrestricted in this
deployment, so none of this was theoretical.

The fix is a positive procedure allowlist, checked before injection. A denylist
cannot work here: the failure is structural, not a matter of naming the right
procedures.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db.tenant_filter import (  # noqa: E402
    TenantScopeError,
    find_disallowed_procedure,
    scope_query,
)

ANCHOR = "OPTIONAL MATCH (d:Domain) WITH d LIMIT 1 "


class ProcedureBypassRegressionTests(unittest.TestCase):
    """The exact payloads that worked, each must now be refused."""

    def _refused(self, cypher: str, because: str):
        with self.assertRaises(TenantScopeError, msg=f"STILL APPROVED: {cypher[:80]}") as ei:
            scope_query(cypher, "attacker-user", "attacker-project")
        self.assertIn("not permitted", str(ei.exception), because)

    def test_cross_tenant_read_via_apoc_cypher_run(self):
        self._refused(
            ANCHOR + 'CALL apoc.cypher.run("MATCH (n) WHERE n.user_id IS NOT NULL '
            'RETURN DISTINCT n.user_id AS uid", {}) YIELD value RETURN value.uid',
            "the confirmed live cross-tenant read",
        )

    def test_cross_tenant_write_via_apoc_cypher_runMany(self):
        self._refused(
            ANCHOR + 'CALL apoc.cypher.runMany("CREATE (x:Pwn {a:1})", {}) '
            "YIELD result RETURN result",
            "a cross-tenant write",
        )

    def test_write_keyword_hidden_by_a_unicode_escape(self):
        # Cypher decodes \\u0043 -> C at parse time. The raw text a regex sees
        # never contains "CREATE", so the write-clause guard returned None.
        # The escape itself is now refused before the procedure allowlist runs
        # (test_tenant_filter_unicode_escape.py), so only the refusal is asserted.
        cypher = (ANCHOR + 'CALL apoc.cypher.runMany("\\u0043REATE (x:Pwn {a:1})", {}) '
                  "YIELD result RETURN result")
        with self.assertRaises(TenantScopeError, msg=f"STILL APPROVED: {cypher[:80]}"):
            scope_query(cypher, "attacker-user", "attacker-project")

    def test_ssrf_via_apoc_load_json(self):
        self._refused(
            'CALL apoc.load.json("http://169.254.169.254/latest/meta-data/") '
            "YIELD value RETURN value",
            "an SSRF from the database container",
        )

    def test_every_apoc_cypher_runner_is_refused(self):
        for proc in (
            "apoc.cypher.run",
            "apoc.cypher.runMany",
            "apoc.cypher.runManyReadOnly",
            "apoc.cypher.runTimeboxed",
            "apoc.cypher.runWrite",
            "apoc.cypher.doIt",
            "apoc.cypher.runSchema",
        ):
            self._refused(
                ANCHOR + f'CALL {proc}("MATCH (n) RETURN n", {{}}) YIELD value RETURN value',
                f"{proc} takes Cypher as an argument",
            )

    def test_every_apoc_load_variant_is_refused(self):
        for proc in ("apoc.load.json", "apoc.load.jsonParams", "apoc.load.xml", "apoc.load.csv"):
            self._refused(
                f'CALL {proc}("http://evil.example/") YIELD value RETURN value',
                f"{proc} fetches from outside",
            )

    def test_dbms_and_db_admin_procedures_are_refused(self):
        for proc in ("dbms.listQueries", "dbms.security.listUsers", "db.index.fulltext.queryNodes"):
            self._refused(
                f"CALL {proc}() YIELD value RETURN value",
                f"{proc} is not a graph read",
            )

    def test_case_and_spacing_do_not_evade_the_check(self):
        for variant in (
            "call apoc.cypher.run",
            "CALL   apoc.cypher.run",
            "CaLl\tapoc.cypher.run",
            "CALL\napoc.cypher.run",
        ):
            self._refused(
                ANCHOR + f'{variant}("MATCH (n) RETURN n", {{}}) YIELD value RETURN value',
                "case/whitespace variant",
            )


class LegitimateQueriesStillWorkTests(unittest.TestCase):
    """The fix must not break the queries the product actually runs."""

    def _approved(self, cypher: str):
        out = scope_query(cypher, "u1", "p1")
        self.assertIn("$tenant_user_id", out)
        return out

    def test_a_plain_labelled_read_is_approved_and_scoped(self):
        out = self._approved("MATCH (i:IP) RETURN i.address")
        self.assertIn("$tenant_project_id", out)

    def test_an_unlabelled_pattern_is_still_scoped_not_refused(self):
        # The older regression: MATCH (n) must be SCOPED, not rejected.
        self._approved("MATCH (n) RETURN n")

    def test_a_multi_hop_traversal_is_approved(self):
        self._approved(
            "MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP) "
            "RETURN d.name, s.name, i.address"
        )

    def test_a_CALL_SUBQUERY_is_not_mistaken_for_a_procedure(self):
        # `CALL { ... }` has no procedure name and is scoped like any other
        # clause. Refusing it would break legitimate generated Cypher.
        self._approved(
            "MATCH (d:Domain) CALL { WITH d MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain) "
            "RETURN s LIMIT 5 } RETURN d.name, s.name"
        )

    def test_a_UNION_is_approved(self):
        self._approved("MATCH (a:IP) RETURN a.address AS v UNION MATCH (b:Domain) RETURN b.name AS v")

    def test_an_aggregation_is_approved(self):
        self._approved("MATCH (v:Vulnerability) RETURN v.severity, count(*) ORDER BY count(*) DESC")

    def test_a_procedure_NAME_inside_a_string_is_not_a_false_positive(self):
        # A finding's description could legitimately mention the text.
        self._approved(
            "MATCH (f:Finding) WHERE f.description CONTAINS "
            "'CALL apoc.cypher.run is dangerous' RETURN f.title"
        )

    def test_a_procedure_name_in_a_comment_is_not_a_false_positive(self):
        self._approved("// CALL apoc.cypher.run\nMATCH (i:IP) RETURN i.address")


class FindDisallowedProcedureUnitTests(unittest.TestCase):
    def test_returns_the_offending_name(self):
        self.assertEqual(
            find_disallowed_procedure('CALL apoc.cypher.run("x", {}) YIELD value RETURN value'),
            "apoc.cypher.run",
        )

    def test_returns_none_for_a_clean_query(self):
        self.assertIsNone(find_disallowed_procedure("MATCH (i:IP) RETURN i"))

    def test_the_allowlist_is_positive_not_a_denylist(self):
        # An invented procedure nobody has denylisted must still be refused:
        # that is the whole point of a positive list.
        self.assertEqual(
            find_disallowed_procedure("CALL some.brand.newProcedure() YIELD x RETURN x"),
            "some.brand.newProcedure",
        )

    def test_the_fixed_schema_op_is_allowed(self):
        # /graph/exec op="schema" is server-controlled, never caller Cypher.
        self.assertIsNone(find_disallowed_procedure("CALL db.schema.visualization()"))


if __name__ == "__main__":
    unittest.main()
