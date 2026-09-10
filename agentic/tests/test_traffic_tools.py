"""
Unit tests for the captured-traffic read tools' query builders (Phase 4 §10.4/§10.6).

Focus: the proxy_query CONSTRAINED BUILDER — the security-critical part. It must
only ever emit allowlisted columns/aggregations/operators, so a prompt-injected
spec can't reach another table, add OR-escapes, or reference the tenant columns
(project_id/user_id are hard-forced by the tool, NOT allowlisted here). Plus the
curl-render shell-quoting and the param classifier.

Runs in the redamon-agent image (needs psycopg + langchain_core):
  docker run --rm --entrypoint python3 -v "$PWD:/work:ro" -w /work redamon-agent:latest \
    -m unittest agentic.tests.test_traffic_tools
"""
from __future__ import annotations

import os
import sys
import unittest

_AGENTIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _AGENTIC not in sys.path:
    sys.path.insert(0, _AGENTIC)

import traffic_tools as tt  # noqa: E402


class TestSelectBuilder(unittest.TestCase):
    def test_star_default(self):
        self.assertEqual(tt._build_select(None), "*")

    def test_columns_and_aggs(self):
        sql = tt._build_select([{"col": "host"}, {"agg": "count", "as": "n"}])
        self.assertIn("host", sql)
        self.assertIn('count(*) AS "n"', sql)

    def test_agg_over_column(self):
        self.assertIn("avg(response_time_ms)", tt._build_select([{"agg": "avg", "col": "response_time_ms"}]))

    def test_rejects_non_allowlisted_column(self):
        with self.assertRaises(ValueError):
            tt._build_select([{"col": "user_id"}])       # tenant col not selectable
        with self.assertRaises(ValueError):
            tt._build_select([{"col": "resp_body"}])     # body not selectable via query
        with self.assertRaises(ValueError):
            tt._build_select([{"col": "password); DROP"}])

    def test_rejects_bad_agg(self):
        with self.assertRaises(ValueError):
            tt._build_select([{"agg": "sleep", "col": "id"}])

    def test_alias_is_sanitized(self):
        sql = tt._build_select([{"col": "host", "as": 'x"; DROP TABLE'}])
        # non-word chars stripped -> no quote/semicolon can escape the identifier
        self.assertNotIn(";", sql)
        self.assertNotIn("DROP TABLE", sql.replace("DROPTABLE", ""))


class TestWhereBuilder(unittest.TestCase):
    def test_rejects_tenant_columns(self):
        # project_id / user_id are NOT allowlisted, so the LLM can never widen scope.
        for col in ("project_id", "user_id"):
            with self.assertRaises(ValueError):
                tt._build_where([{"col": col, "op": "=", "val": "x"}], {})

    def test_rejects_bad_op(self):
        with self.assertRaises(ValueError):
            tt._build_where([{"col": "host", "op": "; DROP", "val": "x"}], {})

    def test_parameterizes_values(self):
        params: dict = {}
        sql = tt._build_where([{"col": "host", "op": "=", "val": "evil' OR 1=1"}], params)
        self.assertIn("host = %(w0)s", sql)          # value is a bound param, not inlined
        self.assertEqual(params["w0"], "evil' OR 1=1")
        self.assertTrue(sql.startswith(" AND "))     # only ANDs onto the forced tenant scope

    def test_like_wraps_wildcards(self):
        params: dict = {}
        tt._build_where([{"col": "path", "op": "like", "val": "admin"}], params)
        self.assertEqual(params["w0"], "%admin%")

    def test_null_ops_take_no_value(self):
        self.assertEqual(tt._build_where([{"col": "session_id", "op": "is_null"}], {}), " AND session_id IS NULL")


class TestGroupOrder(unittest.TestCase):
    def test_group_allowlist(self):
        self.assertEqual(tt._build_group(["host", "method"]), " GROUP BY host, method")
        with self.assertRaises(ValueError):
            tt._build_group(["user_id"])

    def test_order_allows_col_or_alias(self):
        self.assertIn("host ASC", tt._build_order([{"col": "host", "dir": "asc"}]))
        self.assertIn('"n" DESC', tt._build_order([{"as": "n", "dir": "desc"}]))

    def test_order_rejects_injection(self):
        with self.assertRaises(ValueError):
            tt._build_order([{"col": "host; DROP TABLE x"}])


class TestSearchWhere(unittest.TestCase):
    def test_always_scoped_to_tenant(self):
        params = {"p": "P", "u": "U"}
        where = tt._build_search_where({"host": "x", "only5xx": True}, params)
        self.assertIn("project_id = %(p)s", where)
        self.assertIn("user_id = %(u)s", where)
        self.assertIn("host = %(host)s", where)
        self.assertTrue(any("status_code >= 500" in w for w in where))


class TestHelpers(unittest.TestCase):
    def test_classify_value(self):
        self.assertEqual(tt._classify_value("12345"), "sequential-id")
        self.assertEqual(tt._classify_value("550e8400-e29b-41d4-a716-446655440000"), "uuid")
        self.assertEqual(tt._classify_value("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc"), "jwt")

    def test_shell_quote_neutralizes_injection(self):
        # Standard POSIX single-quote escaping: every internal ' becomes '\'' and
        # the whole thing is wrapped in quotes, so the shell reads it as one literal.
        self.assertEqual(tt._shell_quote("a'b"), "'a'\\''b'")
        self.assertEqual(tt._shell_quote("'; rm -rf / #"), "''\\''; rm -rf / #'")


ORIGIN = {
    "method": "GET", "scheme": "https", "host": "target.test", "port": 443,
    "path": "/api/item", "query": "?id=42",
    "req_headers": {"Cookie": "sid=alice", "Authorization": "Bearer AAA", "User-Agent": "x"},
    "req_body": None,
}


class TestReplayBuilder(unittest.TestCase):
    def test_host_is_pinned_to_origin(self):
        # A mutate that tries to change the host / Host header must NOT retarget.
        args = tt.build_replay_curl(ORIGIN, {"headers": {"Host": "evil.test"}, "path": "/x"})
        self.assertIn("https://target.test/x", args)
        self.assertNotIn("evil.test", args)

    def test_param_mutation(self):
        args = tt.build_replay_curl(ORIGIN, {"param": {"id": "99"}})
        self.assertIn("id=99", args)
        self.assertNotIn("id=42", args)

    def test_auth_context_swap_drops_headers(self):
        args = tt.build_replay_curl(ORIGIN, {"dropHeaders": ["Cookie", "Authorization"]})
        self.assertNotIn("sid=alice", args)
        self.assertNotIn("Bearer AAA", args)

    def test_cookie_replace(self):
        args = tt.build_replay_curl(ORIGIN, {"cookie": "sid=bob"})
        self.assertIn("sid=bob", args)
        self.assertNotIn("sid=alice", args)

    def test_method_override(self):
        self.assertIn("-X DELETE", tt.build_replay_curl(ORIGIN, {"method": "delete"}))

    def test_args_are_shell_safe(self):
        # An injection attempt in a mutated value must be shlex-quoted, not raw.
        args = tt.build_replay_curl(ORIGIN, {"param": {"id": "1; rm -rf /"}})
        self.assertNotIn("; rm -rf /", args.replace("'1; rm -rf /'", ""))


class TestFuzzBuilder(unittest.TestCase):
    def test_iterates_payloads_over_param(self):
        variants = list(tt.build_fuzz_curls(ORIGIN, "id", ["1", "2", "' OR 1=1"]))
        self.assertEqual(len(variants), 3)
        self.assertIn("id=2", variants[1][1])
        # each is still host-pinned
        self.assertTrue(all("target.test" in v[1] for v in variants))

    def test_payload_cap(self):
        variants = list(tt.build_fuzz_curls(ORIGIN, "id", [str(i) for i in range(200)]))
        self.assertEqual(len(variants), tt._FUZZ_MAX_PAYLOADS)

    def test_payload_is_url_encoded_no_param_or_host_injection(self):
        # A fuzz payload is a VALUE: "&"/"@" in it must be percent-encoded so it
        # can neither inject an extra query param nor open a URL authority.
        import shlex
        from urllib.parse import urlsplit, parse_qs
        variants = dict(tt.build_fuzz_curls(ORIGIN, "id", ["1&admin=1", "@evil.test"]))
        for payload in ("1&admin=1", "@evil.test"):
            url = shlex.split(variants[payload])[-1]
            parts = urlsplit(url)
            self.assertEqual(parts.netloc, "target.test")   # host still pinned
            self.assertNotIn("evil.test", parts.netloc)
            q = parse_qs(parts.query)
            self.assertNotIn("admin", q)                     # "&" did not add a param
            self.assertEqual(q.get("id"), [payload])         # value carried verbatim (decoded)


if __name__ == "__main__":
    unittest.main()
