"""REGRESSION: a \\uXXXX escape made the scoper and Neo4j read two different queries.

Found by the AI Navigator security review and CONFIRMED live before the fix:
tenant A's `run_cypher` returned tenant B's Subdomain names, and made the Neo4j
container fetch a URL with `apoc.load.json`.

Neo4j decodes `\\uXXXX` before it lexes the query (its own syntax errors quote
the decoded text: `'p\\u0027'` comes back as `'p''`). `code_positions()` reads
the raw text, where `\\u` is an ordinary escape inside a string literal. So in

    MATCH (s:Subdomain) RETURN 'x\\u0027 AS name
    UNION MATCH (n:Subdomain) RETURN n.name AS name //' AS name

the scoper sees one string literal and scopes `(s:Subdomain)` only, while Neo4j
closes the string at `\\u0027` and runs the UNION branch with no tenant filter
(the trailing `//` comments out the rest). Every check that reads code - the
node-pattern scan, the procedure and function allowlists, the write regex, the
display-only names - judged the wrong query. The escape also spells a name the
checks look for (`s.\\u0073ecret_value` reads `secret_value`), in backticks too.

The fix refuses the escape before any other check: no graph read needs one.
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from graph_db.tenant_filter import TenantScopeError, scope_query  # noqa: E402

TENANT = ("attacker-user", "attacker-project")


class UnicodeEscapeRegressionTests(unittest.TestCase):

    def _refused(self, cypher: str):
        with self.assertRaises(TenantScopeError, msg=f"STILL APPROVED: {cypher[:90]}") as ei:
            scope_query(cypher, *TENANT)
        self.assertIn("escape", str(ei.exception))

    def test_an_escaped_quote_hides_an_unscoped_union_branch(self):
        self._refused(
            "MATCH (s:Subdomain) RETURN 'x\\u0027 AS name "
            "UNION MATCH (n:Subdomain) RETURN n.name AS name //' AS name"
        )

    def test_an_escaped_quote_hides_a_url_fetching_procedure(self):
        self._refused(
            "MATCH (s:Subdomain) RETURN 'x\\u0027 AS name UNION CALL apoc.load.json(\"http://192.0.2.1/\") "
            "YIELD value RETURN value.v AS name //' AS name"
        )

    def test_an_escape_spells_a_display_only_name(self):
        self._refused("MATCH (s:Secret) RETURN s.\\u0073ecret_value AS v LIMIT 5")
        self._refused("MATCH (s:Secret) RETURN s.`\\u0073ecret_value` AS v LIMIT 5")
        self._refused("MATCH (s:Secret) RETURN s.secret\\u005fvalue AS v LIMIT 5")

    def test_any_escape_is_refused_even_inside_a_string(self):
        # Refused rather than decoded: mirroring Neo4j's decoder is a second parser to trust.
        self._refused("MATCH (s:Subdomain) WHERE s.name = 'caf\\u00e9.example.test' RETURN s.name LIMIT 5")
        self._refused("MATCH (s:Subdomain) WHERE s.name = 'a\\\\u0041' RETURN s.name LIMIT 5")

    def test_a_backslash_that_is_not_an_escape_still_passes(self):
        out = scope_query("MATCH (s:Subdomain) WHERE s.name STARTS WITH 'C:\\\\users' RETURN s.name LIMIT 5", *TENANT)
        self.assertIn("project_id: $tenant_project_id", out)
        out = scope_query("MATCH (s:Subdomain) WHERE s.name = 'caf\u00e9.example.test' RETURN s.name LIMIT 5", *TENANT)
        self.assertIn("project_id: $tenant_project_id", out)


if __name__ == "__main__":
    unittest.main()
