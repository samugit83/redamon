"""REGRESSION: two shapes that read across tenants past the pattern-based scoper.

Both were reproduced against the running stack (a query that `scope_query`
approved for ONE project returned data from all 27), and both share a cause:
tenant scoping rewrites NODE PATTERNS, so anything that reaches data without
being written as a node pattern is invisible to it.

1. APOC FUNCTIONS.  The procedure allowlist only inspects `CALL <name>`. APOC
   also exposes the same capability as FUNCTIONS, which need no CALL and are
   legal anywhere an expression is:

       MATCH (d:Domain) WITH d LIMIT 1
       RETURN apoc.cypher.runFirstColumnSingle('MATCH (n) RETURN ...', {})

   The inner query is a string literal, so it is never scoped. `apoc.load.*`
   points the same hole outward as an SSRF from inside the database container.

2. VARIABLE-LENGTH PATHS.  The intermediate nodes of `[*]` / `{n,m}` are never
   written as `()` patterns, so they get neither the tenant filter nor the
   `!Muted` exclusion, while the reference labels (CVE/MitreData/Capec) are
   exempt once ONE tenant-anchored pattern exists:

       MATCH (t:Technology) WITH t LIMIT 1
       MATCH p=(:CVE)-[*2]-(:CVE) UNWIND nodes(p) AS n RETURN n

   walks from the shared CVE nodes straight into other projects' nodes. A
   quantified RELATIONSHIP (`-[:R]->+`, `-->*`, `-[:R]->{,3}`) does the same and
   was approved until the fix below.

3. A KEYWORD READ AS A FUNCTION NAME.  `MATCH(n)` (no space) put a word right
   against the paren, so the scanner took it for a call like `count(n)` and
   never scoped the pattern: `MATCH(n) RETURN n.name` returned every tenant's
   nodes, as did `OPTIONAL MATCH(n)`, `CALL{MATCH(x) ...}` and `UNION MATCH(x)`.

4. A PATTERN THE SCANNER DID NOT SEE AS ONE.  A clause word inside a pattern
   (`-[r WHERE ...]->`, `{limit: 1}`, a variable named `on`) ended the pattern
   region, so the next comma-separated `(c)` ran unscoped; the short subquery
   forms `COUNT { (x:Secret) }` / `EXISTS { (x) }` were never a region at all.

5. SHAPES THAT CANNOT BE SCOPED.  `SHOW TRANSACTIONS` lists every tenant's
   running queries with their parameters; a property map naming `user_id` /
   `project_id` itself could outvote the injected filter; and one label regex
   backtracked exponentially, so a 30-character label hung the agent.

6. A CLAUSE WORD AS A PATH VARIABLE.  Neo4j 5.26 accepts every clause word as
   a path variable (`MATCH where = (m) RETURN where`, `MATCH (a:Domain), as =
   (m)`), and reads `$` as a name character (`AS$p` is one variable). The
   scanner took the word for the clause, ended the pattern region, and `(m)`
   ran with no filter at all. Same review: a tenant map nested inside a value
   (`{name: left('', size(keys({user_id: $tenant_user_id, ...})))}`) counted as
   the node's own filter, and `-[r*1..2 {tags: [1]}]-` hid its `*` behind the
   nested list.

Run: python -m unittest tests.test_tenant_filter_function_and_path_bypass
"""
import os
import re
import sys
import time
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

from graph_db.tenant_filter import (  # noqa: E402
    TenantScopeError,
    find_disallowed_call,
    find_unscoped_node_pattern,
    has_variable_length_path,
    inject_tenant_filter,
    scope_query,
)

ANCHOR = "MATCH (d:Domain) WITH d LIMIT 1 "
UID, PID = "attacker-user", "attacker-project"


def refused(cypher: str) -> bool:
    try:
        scope_query(cypher, UID, PID)
        return False
    except TenantScopeError:
        return True


def approved(cypher: str) -> str:
    return scope_query(cypher, UID, PID)


def scoped(out: str, var: str) -> bool:
    """True when the pattern binding `var` carries both tenant keys."""
    return bool(re.search(
        r'\(' + re.escape(var) + r'\s*:[^()]*\{[^()]*user_id: \$tenant_user_id, '
        r'project_id: \$tenant_project_id\}\)', out))


class ApocFunctionBypassTests(unittest.TestCase):
    def test_the_confirmed_cross_tenant_read_is_refused(self):
        self.assertTrue(refused(
            ANCHOR + "RETURN apoc.cypher.runFirstColumnSingle("
            "'MATCH (n) WHERE n.project_id IS NOT NULL "
            "RETURN count(DISTINCT n.project_id)', {}) AS projects"
        ))

    def test_every_function_form_that_runs_cypher_or_fetches_is_refused(self):
        for fn in (
            "apoc.cypher.runFirstColumnSingle",
            "apoc.cypher.runFirstColumnMany",
            "apoc.load.json",
            "apoc.load.csv",
            "apoc.load.xml",
            "apoc.text.regexGroups",
            "apoc.util.sleep",
        ):
            with self.subTest(fn=fn):
                self.assertTrue(refused(ANCHOR + f"RETURN {fn}('x', {{}}) AS v"), fn)

    def test_the_name_cannot_be_hidden_by_quoting_spacing_or_comments(self):
        for variant in (
            "`apoc`.`cypher`.`runFirstColumnSingle`",
            "`apoc.cypher.runFirstColumnSingle`",
            "apoc . cypher . runFirstColumnSingle",
            "apoc/**/.cypher.runFirstColumnSingle",
            "APOC.CYPHER.RUNFIRSTCOLUMNSINGLE",
            "apoc\n.cypher\n.runFirstColumnSingle",
        ):
            with self.subTest(variant=variant):
                self.assertTrue(
                    refused(ANCHOR + f"RETURN {variant}('x', {{}}) AS v"), variant
                )

    def test_a_call_procedure_form_is_still_refused(self):
        # The path that already worked must not regress.
        self.assertTrue(refused(
            ANCHOR + "CALL apoc.cypher.run('MATCH (n) RETURN n', {}) YIELD value RETURN value"
        ))

    def test_an_invented_namespace_is_refused_too(self):
        # A positive allowlist, not a denylist: a namespace nobody thought of.
        self.assertTrue(refused(ANCHOR + "RETURN some.brand.newFunction(d) AS v"))

    def test_an_apoc_name_in_a_string_or_comment_is_not_a_false_positive(self):
        approved("MATCH (f:Finding) WHERE f.description CONTAINS "
                 "'apoc.load.json(x) is dangerous' RETURN f.title")
        approved("// apoc.cypher.runFirstColumnSingle\nMATCH (i:IP) RETURN i.address")


class LegitimateFunctionsStillWorkTests(unittest.TestCase):
    def test_builtin_namespaced_functions_are_approved(self):
        for expr in (
            "duration.between(i.first_seen, i.last_seen)",
            "point.distance(i.loc, i.loc)",
            "date.truncate('month', i.first_seen)",
            "datetime.fromepochmillis(i.ts)",
        ):
            with self.subTest(expr=expr):
                approved(f"MATCH (i:IP) RETURN {expr} AS v")

    def test_plain_unnamespaced_functions_are_approved(self):
        approved("MATCH (v:Vulnerability) RETURN count(v), collect(v.name), "
                 "toString(id(v)), size(v.name), coalesce(v.severity, 'n/a')")

    def test_property_access_and_map_projection_are_not_calls(self):
        # `n.name(` never appears, but `n{.a, .b}` and `n.a` are dotted too.
        approved("MATCH (n:Domain) RETURN n{.name, .status} AS m, n.name")

    def test_find_disallowed_call_returns_the_name(self):
        self.assertEqual(
            find_disallowed_call("RETURN apoc.load.json('x') AS v"), "apoc.load.json"
        )
        self.assertIsNone(find_disallowed_call("MATCH (i:IP) RETURN i.address"))


class VariableLengthPathBypassTests(unittest.TestCase):
    def test_the_confirmed_walk_through_reference_nodes_is_refused(self):
        self.assertTrue(refused(
            "MATCH (t:Technology) WITH t LIMIT 1 "
            "MATCH p=(:CVE)-[*2]-(:CVE) UNWIND nodes(p) AS n "
            "RETURN [x IN nodes(p) | [id(x), labels(x), x.name]]"
        ))

    def test_every_variable_length_spelling_is_refused(self):
        for hop in (
            "-[*]->", "-[*2]->", "-[*1..3]->", "-[*..3]->", "-[*0..]->",
            "-[:HAS_PORT*]->", "-[:HAS_PORT*1..2]->", "-[r:RESOLVES_TO*1..2]->",
            "-[:A|B*2]->", "<-[*2]-", "-[*]-",
        ):
            with self.subTest(hop=hop):
                self.assertTrue(
                    refused(f"MATCH (a:Domain){hop}(b:IP) RETURN a, b"), hop
                )

    def test_quantified_paths_and_relationships_are_refused(self):
        for q in (
            "MATCH ((a:Domain)-[:HAS_SUBDOMAIN]->(b:Subdomain)){1,3} RETURN a",
            "MATCH (a:Domain)-[:HAS_SUBDOMAIN]->{1,3}(b:Subdomain) RETURN b",
            "MATCH (a:Domain) ((x)-[:R]->(y)){2} (b:IP) RETURN b",
        ):
            with self.subTest(q=q):
                self.assertTrue(refused(q), q)

    def test_the_agent_prompt_no_longer_teaches_a_variable_length_walk(self):
        # The prompt's own decisions example used `[:NEXT_STEP*0..]`; leaving it
        # would teach the model a query that always fails.
        from agentic.prompts import TEXT_TO_CYPHER_SYSTEM
        for line in TEXT_TO_CYPHER_SYSTEM.splitlines():
            if line.strip().startswith(("//", "-", "#", "Bad", "  Bad")):
                continue
            self.assertFalse(
                has_variable_length_path(line),
                f"the Cypher generator prompt teaches a refused query: {line.strip()}",
            )


class LegitimateShapesStillWorkTests(unittest.TestCase):
    def test_fixed_length_multi_hop_traversals_are_approved(self):
        approved("MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(i:IP)"
                 "-[:HAS_PORT]->(p:Port) RETURN d.name, i.address, p.number")

    def test_a_star_inside_a_string_literal_is_not_a_path(self):
        approved("MATCH (i:IP) WHERE i.note = '[*] scanned' RETURN i")
        approved("MATCH (i:IP) WHERE i.note CONTAINS '-[*2]->' RETURN i")

    def test_list_slices_maps_and_comprehensions_are_not_paths(self):
        approved("MATCH (d:Domain) RETURN collect(d.name)[0..5] AS first5")
        approved("MATCH (d:Domain) RETURN d{.name} AS m")
        approved("MATCH (v:Vulnerability) RETURN [x IN collect(v.name) WHERE size(x) > 3] AS n")
        approved("MATCH (v:Vulnerability) RETURN {a: 1, b: {c: 2}} AS m, count(*) * 2")

    def test_a_comment_mentioning_a_path_is_not_a_path(self):
        approved("// walks -[*1..3]->\nMATCH (i:IP) RETURN i.address")

    def test_the_reference_chain_from_tenant_data_still_works(self):
        # The exemption is intact: an anchored, fixed-length reference traversal.
        out = approved("MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE)-[:HAS_CWE]->"
                       "(m:MitreData)-[:HAS_CAPEC]->(k:Capec) RETURN t.name, c.id, m.cwe_id, k.capec_id")
        self.assertIn("$tenant_user_id", out)

    def test_has_variable_length_path_unit(self):
        self.assertTrue(has_variable_length_path("MATCH (a)-[*]->(b) RETURN a"))
        self.assertFalse(has_variable_length_path("MATCH (a)-[:R]->(b) RETURN a"))



class KeywordBeforeParenTests(unittest.TestCase):
    """A clause keyword written against its paren opens a pattern, never a call."""

    def test_the_confirmed_read_of_every_tenant_is_scoped(self):
        out = approved("MATCH(n) RETURN n.name")
        self.assertTrue(scoped(out, "n"), out)

    def test_every_keyword_spelling_is_scoped(self):
        for query, var in (
            ("MATCH(n:Secret) RETURN n.name", "n"),
            ("match(n) RETURN n.name", "n"),
            ("MATCH/**/(n) RETURN n.name", "n"),
            ("OPTIONAL MATCH(n) RETURN n.name", "n"),
            ("MATCH (d:Domain) OPTIONAL MATCH(x)-->(d) RETURN x.name", "x"),
            ("MATCH (a:IP) RETURN a.address AS v UNION MATCH(b) RETURN b.name AS v", "b"),
            ("MATCH (a:IP) RETURN a.address AS v UNION ALL MATCH(b) RETURN b.name AS v", "b"),
            ("MATCH (d:Domain) CALL{MATCH(x) RETURN x} RETURN x.name", "x"),
            ("MATCH (d:Domain) WHERE EXISTS{MATCH(x:Secret)} RETURN d", "x"),
            ("MATCH (d:Domain) RETURN COUNT{MATCH(x)} AS c", "x"),
            ("MATCH (d:Domain) RETURN COLLECT{MATCH(x) RETURN x.name} AS c", "x"),
            ("MATCH (d:Domain) WHERE NOT(d)-->(x) RETURN d", "d"),
            ("MATCH (d:Domain) WHERE d.a = 1 AND(d)-->(:IP) RETURN d", "d"),
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, var), out)

    def test_a_real_function_call_is_left_alone(self):
        out = approved("MATCH (n:Domain) RETURN count(n), collect(n.name), "
                       "toLower(n.name), coalesce(n.a, 'x'), size(n.name)")
        for call in ("count(n)", "collect(n.name)", "toLower(n.name)", "size(n.name)"):
            self.assertIn(call, out)

    def test_a_namespaced_or_quoted_function_name_is_still_a_call(self):
        out = approved("MATCH (i:IP) RETURN date.truncate('month', i.first_seen) AS m, `count`(i) AS c")
        self.assertIn("`count`(i)", out)

    def test_the_import_list_of_a_scoped_subquery_is_not_a_pattern(self):
        out = approved("MATCH (d:Domain) CALL (d) { MATCH (d)-[:HAS_SUBDOMAIN]->(s:Subdomain) "
                       "RETURN s } RETURN s.name")
        self.assertIn("CALL (d) {", out)
        self.assertTrue(scoped(out, "s"), out)


class ClauseWordsInsideAPatternTests(unittest.TestCase):
    """A clause word inside a pattern does not end the pattern region."""

    def test_the_next_comma_separated_pattern_is_still_scoped(self):
        for query in (
            "MATCH (a:Domain)-[r WHERE r.weight > 1]->(b:IP), (c) RETURN c.name",
            "MATCH (a:Domain {limit: 1}), (c) RETURN c.name",
            "MATCH (a:Domain {name: $as}), (c) RETURN c.name",
            "MATCH (on:Domain), (c) RETURN c.name",
            "MATCH (with:Domain), (c) RETURN c.name",
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, "c"), out)

    def test_a_property_named_like_a_clause_still_lets_the_where_close_the_region(self):
        approved("MATCH (n:Domain) WHERE n.limit > 1 AND (n.name = 'x') RETURN n.limit")


class SubqueryShapesTests(unittest.TestCase):
    def test_the_short_count_and_exists_forms_are_scoped(self):
        for query, var in (
            ("MATCH (d:Domain) RETURN COUNT { (x:Secret) } AS c", "x"),
            ("MATCH (d:Domain) RETURN COUNT{(x)} AS c", "x"),
            ("MATCH (d:Domain) WHERE EXISTS { (x:Secret {name: 'k'}) } RETURN d", "x"),
            ("MATCH (d:Domain) WHERE EXISTS { (d)-->(x) WHERE x.a = 1 } RETURN d", "x"),
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, var), out)

    def test_the_full_subquery_forms_are_scoped(self):
        for query, var in (
            ("MATCH (d:Domain) WHERE EXISTS { MATCH (x:Secret) WHERE x.a = 1 } RETURN d", "x"),
            ("MATCH (d:Domain) RETURN COLLECT { MATCH (x:Secret) RETURN x.name } AS c", "x"),
            ("MATCH (d:Domain) CALL { MATCH (x) RETURN x } RETURN x.name", "x"),
            ("MATCH (d:Domain) CALL { WITH d MATCH (d)-->(x) RETURN x } RETURN x.name", "x"),
            ("MATCH (a:Domain) WHERE EXISTS { MATCH (a)-->(b) WHERE EXISTS { (b)-->(c) } } RETURN a", "c"),
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, var), out)

    def test_the_clause_after_a_subquery_is_read_as_before_it(self):
        # The `}` restores the WHERE context, so the parenthesised expression after
        # it is an expression, not a malformed node pattern to refuse.
        approved("MATCH (d:Domain) WHERE EXISTS { (d)-->(:IP) } AND (d.name = 'x') RETURN d")


class OddShapesTests(unittest.TestCase):
    def test_optional_match_and_union_branches_are_scoped(self):
        out = approved("MATCH (a:IP) OPTIONAL MATCH (a)-->(n) RETURN n.name AS v "
                       "UNION MATCH (b) RETURN b.name AS v")
        self.assertTrue(scoped(out, "n"), out)
        self.assertTrue(scoped(out, "b"), out)

    def test_pattern_comprehensions_are_scoped(self):
        for query, var in (
            ("MATCH (d:Domain) RETURN [(d)-->(x) | x.name] AS names", "x"),
            ("MATCH (d:Domain) RETURN [(d)-[:R]->(x:IP) WHERE x.a = 1 | x] AS ips", "x"),
            ("MATCH (d:Domain) RETURN [p = (d)-->(x) | p] AS paths", "x"),
            ("MATCH (d:Domain) WHERE d.x IN [(d)-->(y) | y.name] RETURN d", "y"),
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, var), out)

    def test_backticked_names_are_scoped(self):
        self.assertIn("$tenant_user_id", approved("MATCH (`n`:`Secret`) RETURN `n`.name"))
        self.assertIn("$tenant_user_id", approved("MATCH (n:`Dom ain`) RETURN n.name"))

    def test_a_paren_in_a_string_or_comment_hides_nothing(self):
        for query, var in (
            ("MATCH (d:Domain) WHERE d.note = '//' MATCH (n) RETURN n.name", "n"),
            ("MATCH (d:Domain) /* ( */ MATCH (n) RETURN n.name", "n"),
            ("MATCH (d:Domain) // a ( comment\nMATCH (n) RETURN n.name", "n"),
            ("MATCH (d:Domain) WHERE d.note = \"it's (\" MATCH (n) RETURN n.name", "n"),
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, var), out)

    def test_a_comment_between_an_arrow_and_its_node_hides_nothing(self):
        for query, var in (
            ("MATCH (d:Domain) RETURN [(d)-->/**/(x) | x.name] AS n", "x"),
            ("MATCH (d:Domain) RETURN [(d)-->// c\n(x) | x.name] AS n", "x"),
            ("MATCH (d:Domain) RETURN [(d)/**/-->(x) | x.name] AS n", "d"),
        ):
            with self.subTest(query=query):
                out = approved(query)
                self.assertTrue(scoped(out, var), out)

    def test_a_pattern_after_a_bar_is_not_a_label_group(self):
        out = inject_tenant_filter("MATCH (d:Domain) RETURN [x IN [1] | (y:Secret)-->()] AS n", UID, PID)
        self.assertTrue(scoped(out, "y"), out)

    def test_a_pattern_inside_a_string_is_data_and_stays_as_written(self):
        out = approved("MATCH (d:Domain) WHERE d.name = 'MATCH(n)' RETURN d")
        self.assertIn("'MATCH(n)'", out)

    def test_fake_tenant_keys_inside_a_string_do_not_count_as_scoped(self):
        out = approved("MATCH (n:Secret {note: 'user_id: $tenant_user_id, "
                       "project_id: $tenant_project_id'}) RETURN n.name")
        self.assertIn("', user_id: $tenant_user_id, project_id: $tenant_project_id})", out)

    def test_a_label_predicate_in_where_is_still_an_expression(self):
        approved("MATCH (n) WHERE (n:Domain OR n:Subdomain) RETURN n.name")
        approved("MATCH (d:Domain) WITH d, d.x AS x WHERE (x IS NULL) RETURN d")
        approved("MATCH (d:Domain) WHERE (d.x IS NOT NULL) RETURN d")

    def test_a_node_shaped_group_is_a_pattern_wherever_it_stands(self):
        self.assertIsNotNone(find_unscoped_node_pattern("RETURN (x:Secret {name: 'k'})"))
        self.assertIn("$tenant_user_id", inject_tenant_filter("RETURN (:Secret)", UID, PID))

    def test_the_is_label_form_cannot_be_scoped_and_is_refused(self):
        self.assertTrue(refused("MATCH (d:Domain), (x IS Secret) RETURN x.name"))
        self.assertTrue(refused("MATCH (on:Domain), (x IS Secret) RETURN x.name"))


class TenantKeysInAPropertyMapTests(unittest.TestCase):
    def test_a_map_naming_the_tenant_keys_itself_is_refused(self):
        for props in (
            "{user_id: 'victim-user', project_id: 'victim-project'}",
            "{user_id: $tenant_user_id, project_id: $tenant_project_id, project_id: 'victim'}",
            "{user_id: $tenant_user_id, project_id: $tenant_project_id, `project_id`: 'victim'}",
            "{project_id: 'victim', user_id: $tenant_user_id, project_id: $tenant_project_id}",
        ):
            with self.subTest(props=props):
                self.assertTrue(refused(f"MATCH (n:Secret {props}) RETURN n.name"), props)

    def test_the_exact_tenant_filter_written_by_the_caller_is_accepted(self):
        approved("MATCH (n:Domain {user_id: $tenant_user_id, project_id: $tenant_project_id}) "
                 "RETURN n.name")

    def test_reading_a_tenant_property_is_not_naming_a_key(self):
        out = approved("MATCH (a:Domain) MATCH (b:IP {name: a.project_id}) RETURN b.address")
        self.assertTrue(scoped(out, "b"), out)

    def test_a_tenant_map_nested_in_a_value_is_not_the_nodes_filter(self):
        # The value evaluates to 'x', so before the fix this matched every
        # tenant's nodes named 'x': only a TOP-LEVEL entry filters the node.
        nested = "{user_id: $tenant_user_id, project_id: $tenant_project_id}"
        query = f"MATCH (n {{name: 'x' + left('', size(keys({nested})) - 1)}}) RETURN n"
        self.assertEqual(
            approved(query),
            f"MATCH (n:!Muted {{name: 'x' + left('', size(keys({nested})) - 1), "
            f"user_id: $tenant_user_id, project_id: $tenant_project_id}}) RETURN n",
        )
        for value in (f"[{nested}][0].user_id", f"CASE WHEN true THEN 'x' ELSE {nested} END"):
            with self.subTest(value=value):
                out = approved(f"MATCH (n:Secret {{name: {value}}}) RETURN n")
                self.assertTrue(out.endswith(
                    ", user_id: $tenant_user_id, project_id: $tenant_project_id}) RETURN n"), out)

    def test_a_tenant_parameter_with_a_name_character_after_it_is_another_parameter(self):
        # Neo4j reads `$tenant_user_id$` as the parameter `tenant_user_id$`.
        self.assertTrue(refused(
            "MATCH (n:Secret {user_id: $tenant_user_id$, project_id: $tenant_project_id$}) RETURN n"))

    def test_a_quoted_tenant_parameter_is_the_same_parameter(self):
        out = approved("MATCH (n:Secret {user_id: $`tenant_user_id`, "
                       "project_id: $`tenant_project_id`}) RETURN n.name")
        self.assertIn("(n:Secret&!Muted {user_id: $`tenant_user_id`", out)

    def test_a_key_with_an_escaped_backtick_is_not_a_tenant_key(self):
        # `user``_id` is the key user`_id to Neo4j, not user_id.
        out = approved("MATCH (n:Secret {`user``_id`: $tenant_user_id, "
                       "`project``_id`: $tenant_project_id}) RETURN n.name")
        self.assertTrue(out.endswith(
            ", user_id: $tenant_user_id, project_id: $tenant_project_id}) RETURN n.name"), out)

    def test_a_property_map_that_is_not_key_value_pairs_is_refused(self):
        for props in ("{.name}", "{a: 1} {b: 2}", "{a: 1,}", "{, a: 1}", "{a}"):
            with self.subTest(props=props):
                self.assertTrue(refused(f"MATCH (n:Secret {props}) RETURN n"), props)


class ClauseWordAsPathVariableTests(unittest.TestCase):
    """Every clause word is a legal path variable in Neo4j 5.26 (checked with
    EXPLAIN): the pattern after it is still a pattern and must be scoped."""

    WORDS = ("WHERE", "RETURN", "WITH", "UNWIND", "CALL", "ORDER", "SKIP", "LIMIT",
             "DELETE", "DETACH", "SET", "REMOVE", "FOREACH", "UNION", "YIELD", "ON",
             "USING", "AS", "where", "As")

    def test_after_a_comma(self):
        for word in self.WORDS:
            with self.subTest(word=word):
                out = approved(f"MATCH (a:Domain), {word} = (m:Secret) RETURN m.name")
                self.assertTrue(scoped(out, "m"), out)
                self.assertIsNone(find_unscoped_node_pattern(out))

    def test_right_after_match(self):
        for word in self.WORDS:
            with self.subTest(word=word):
                out = approved(f"MATCH {word} = (m) RETURN m.name")
                self.assertTrue(scoped(out, "m"), out)

    def test_other_spellings_and_places(self):
        for query in (
            "MATCH (a:Domain) OPTIONAL MATCH where = (m) RETURN m.name",
            "MATCH (a:Domain), where/* c */=(m) RETURN m.name",
            "MATCH (a:Domain), where // c\n = (m) RETURN m.name",
            "MATCH (a:Domain), where /* it's */ = (m) RETURN m.name",
            "MATCH (a:Domain) RETURN COUNT { where = (m) } AS n, a.name, 1 AS m",
            "MATCH (a:Domain) WHERE EXISTS { as = (m) } RETURN a.name, 1 AS m",
        ):
            with self.subTest(query=query):
                self.assertTrue(scoped(approved(query), "m"), query)

    def test_a_dollar_sign_is_part_of_the_name(self):
        for query in (
            "MATCH (a:Domain), AS$p = (m) RETURN m.name",
            "MATCH (a:Domain), where$ = (m) RETURN m.name",
            "MATCH return$x = (m) RETURN m.name",
        ):
            with self.subTest(query=query):
                self.assertTrue(scoped(approved(query), "m"), query)

    def test_the_clauses_themselves_still_end_the_pattern(self):
        approved("MATCH (n) WHERE (n:Domain OR n:Subdomain) RETURN n.name")
        approved("MATCH (n:Domain) WHERE n.x = 1 WITH n WHERE (n.y IS NULL) RETURN n")
        approved("MATCH (n:Domain) WHERE 'x' = n.name AND (n:Domain OR n:IP) RETURN n")
        approved("MATCH (n:Domain) WHERE $tenant_user_id = n.user_id RETURN n")


class OddNodeShapeTests(unittest.TestCase):
    """Node patterns Neo4j 5.26 reads that the scanner cannot rewrite: each is
    refused with TenantScopeError wherever it stands, never run and never a
    crash (the webapp's saved-view filter found them, checked with EXPLAIN)."""

    SHAPES = ("(n$)", "(n$:Secret)", "(IS Secret)", "(n IS Secret)", "(WHERE true)",
              "(n:Secret WHERE true)", "(n {.name})")

    def test_refused_wherever_the_pattern_stands(self):
        for shape in self.SHAPES:
            for query in (
                f"MATCH {shape} RETURN 1",
                f"MATCH (a:Domain), {shape} RETURN 1",
                f"MATCH (a:Domain), where = {shape} RETURN 1",
                f"MATCH (a:Domain)-->{shape} RETURN 1",
                f"MATCH (a:Domain) WHERE EXISTS {{ {shape} }} RETURN a",
                f"MATCH (a:Domain) RETURN [(a)-->{shape} | 1] AS x",
            ):
                with self.subTest(query=query):
                    with self.assertRaises(TenantScopeError):
                        scope_query(query, UID, PID)

    def test_a_number_before_a_paren_is_not_a_function_name(self):
        # `2e1(` used to read as a call, so the group after it was skipped.
        try:
            out = approved("MATCH SHORTEST 2e1(n:Domain) RETURN n")
        except TenantScopeError:
            return
        self.assertTrue(scoped(out, "n"), out)

    def test_a_dollar_name_elsewhere_is_harmless(self):
        out = approved("MATCH (a:Domain) WITH a AS x$ MATCH (m) RETURN m.name")
        self.assertTrue(scoped(out, "m"), out)


class QuantifiedRelationshipTests(unittest.TestCase):
    def test_every_quantified_relationship_is_refused(self):
        for hop in (
            "-[:R]->+", "-[:R]->*", "<-[:R]-+", "-[:R]-+", "-->+", "--+", "<--*",
            "-[:R]-> +", "-[:R]->/* x */+", "-[:R]->{,3}", "-->{,2}", "-[:R]->{ 1 , 3 }",
        ):
            with self.subTest(hop=hop):
                self.assertTrue(refused(f"MATCH (a:Domain){hop}(b:IP) RETURN b.address"), hop)

    def test_inside_a_selector_a_subquery_or_a_comprehension_too(self):
        for query in (
            "MATCH p = SHORTEST 1 (a:Domain)-->+(b:IP) RETURN p",
            "MATCH (d:Domain) WHERE EXISTS { (d)-[:R]->+(x:IP) } RETURN d",
            "MATCH (d:Domain) RETURN [(d)-->+(x) | x.name] AS names",
        ):
            with self.subTest(query=query):
                self.assertTrue(refused(query), query)

    def test_arithmetic_and_strings_are_not_quantifiers(self):
        approved("MATCH (n:Domain) RETURN count(*) * 2, (n.a + 1) * 3, n.b + 1")
        approved("MATCH (n:Domain) WHERE n.note = '-[:R]->+' RETURN n")

    def test_a_star_beside_a_nested_list_in_the_brackets_is_still_variable_length(self):
        for rel in ("-[r*1..2 {tags: [1]}]-", "-[r:R*1..2 {tags: [1]}]->",
                    "<-[r * {tags: ['x', [2]]}]-", "-[r*{a: [[1]]}]-", "-[r {a: [1]} *2]-"):
            with self.subTest(rel=rel):
                query = f"MATCH (a:Domain){rel}(b) RETURN a"
                self.assertTrue(has_variable_length_path(query), rel)
                self.assertTrue(refused(query), rel)

    def test_a_nested_list_without_a_star_is_one_hop(self):
        self.assertFalse(has_variable_length_path("MATCH (a)-[r {tags: [1, [2]]}]->(b) RETURN b"))
        self.assertFalse(has_variable_length_path("MATCH (a)-[r {note: '*'}]->(b) RETURN b"))
        approved("MATCH (a:Domain)-[r:R {tags: [1, [2]]}]->(b:IP) RETURN b.address")

    def test_has_variable_length_path_unit(self):
        self.assertTrue(has_variable_length_path("MATCH (a)-[:R]->+(b) RETURN b"))
        self.assertTrue(has_variable_length_path("MATCH (a)-[:R]->{,3}(b) RETURN b"))
        self.assertFalse(has_variable_length_path("MATCH (a)-[:R]->(b) RETURN b"))


class ClausesThatLeaveTheGraphTests(unittest.TestCase):
    def test_show_use_and_load_are_refused(self):
        for query in (
            "SHOW TRANSACTIONS YIELD currentQuery, parameters RETURN currentQuery",
            "show transactions",
            "SHOW PROCEDURES",
            "USE system SHOW USERS",
            "LOAD CSV FROM 'http://example.invalid/x' AS row RETURN row",
        ):
            with self.subTest(query=query):
                self.assertTrue(refused(query), query)

    def test_the_words_as_properties_or_data_are_not_clauses(self):
        approved("MATCH (n:Domain) WHERE n.show = 1 RETURN n.load, 'SHOW TRANSACTIONS' AS s")


class UnreadableInputTests(unittest.TestCase):
    """Every refusal is a TenantScopeError: callers catch only that, so any other
    exception ended `/graph/nl-query` in a 500."""

    def assert_refused_cleanly(self, query):
        with self.assertRaises(TenantScopeError):
            scope_query(query, UID, PID)

    def test_a_unicode_letter_variable_is_refused_not_a_crash(self):
        self.assert_refused_cleanly("MATCH (é) RETURN é")
        self.assert_refused_cleanly("MATCH (é:Domain) RETURN é.name")

    def test_a_unicode_letter_outside_a_pattern_is_fine(self):
        approved("MATCH (n:Domain) RETURN n.name AS città")

    def test_a_backticked_variable_with_a_space_is_scoped(self):
        self.assertTrue(scoped(approved("MATCH (`x y`) RETURN `x y`.name"), "`x y`"))
        self.assertTrue(scoped(approved("MATCH (`a b`:Domain) RETURN `a b`.name"), "`a b`"))

    def test_the_is_label_form_is_refused(self):
        self.assert_refused_cleanly("MATCH (n IS Domain) RETURN n")

    def test_control_characters_in_code_are_refused(self):
        for char in ("\x07", "\x1c", "\x1d", "\x1e", "\x1f", "\x00", "\x7f", "​"):
            with self.subTest(char=repr(char)):
                self.assert_refused_cleanly(f"MATCH (n{char}) RETURN n")
                self.assert_refused_cleanly(f"MATCH{char}(n) RETURN n.name")

    def test_a_control_character_inside_a_string_is_data(self):
        approved("MATCH (n:Domain) WHERE n.note = 'bell\x07 fs\x1c' RETURN n")

    def test_unicode_dashes_and_arrowheads_in_a_relationship_are_refused(self):
        for arrow in ("‐[:R]‐>", "—[:R]—+", "-[:R]—+",
                      "——", "-[:R]-＞", "−->"):
            with self.subTest(arrow=arrow):
                self.assert_refused_cleanly(f"MATCH (a:Domain){arrow}(b) RETURN b.name")
        self.assert_refused_cleanly("MATCH (d:Domain) RETURN [(d)——(x) | x.name] AS n")

    def test_a_dash_inside_a_string_is_data(self):
        approved("MATCH (n:Domain) WHERE n.title CONTAINS '—' RETURN n")

    def test_open_lower_bound_quantifiers_are_refused(self):
        for hop in ("-[:R]->{,3}", "-[:R]->{,}", "-[]-{,2}", "-->{ , 2}"):
            with self.subTest(hop=hop):
                self.assertTrue(refused(f"MATCH (a:Domain){hop}(b:IP) RETURN b"), hop)

    def test_split_arrows_are_still_quantified_relationships(self):
        for hop in ("- ->+", "-[:R]- ->+", "< - -*", "-[:R]- - >+", "- - >{1,2}", "-[:R]- >{,2}"):
            with self.subTest(hop=hop):
                self.assertTrue(refused(f"MATCH (a:Domain){hop}(b:IP) RETURN b"), hop)

    def test_a_backslash_in_a_backticked_name_hides_nothing(self):
        # Neo4j reads `x\` as a name ending at the second backtick, not as an
        # escaped backtick, so the MATCH after it is code.
        out = approved("MATCH (d:Domain) WITH d AS `x\\` MATCH (m) RETURN m.name AS `y`")
        self.assertTrue(scoped(out, "m"), out)

    def test_no_input_raises_anything_but_a_refusal(self):
        for query in (None, 42, "", "(", ")", "MATCH (", "MATCH ()", "`", "'", "/*",
                      "MATCH (n:`unterminated) RETURN n", "MATCH (n {a: 'x}) RETURN n",
                      "MATCH (n:A|) RETURN n", "MATCH (n:!) RETURN n", "MATCH (:) RETURN 1"):
            with self.subTest(query=query):
                try:
                    scope_query(query, UID, PID)
                except TenantScopeError:
                    pass


class ScannerCostTests(unittest.TestCase):
    """A long label used to backtrack exponentially (doubling per character)."""

    def test_a_long_malformed_label_is_refused_quickly(self):
        for query in (
            "MATCH (n:" + "a" * 40 + "%) RETURN n",
            "MATCH (n:A" + " " * 3000 + "%) RETURN n",
            "MATCH (n:" + "a" * 40 + ") WHERE (x:" + "b" * 40 + "%) RETURN n",
        ):
            with self.subTest(query=query[:30]):
                started = time.monotonic()
                refused(query)
                self.assertLess(time.monotonic() - started, 2.0)

if __name__ == "__main__":
    unittest.main()
