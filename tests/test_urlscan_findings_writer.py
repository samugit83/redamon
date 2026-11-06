"""S6: update_graph_from_urlscan_findings, the one writer for every urlscan finding.

IDs carry the tenant and the kind (a new token of the same kind on the same
path is the same finding), every finding has a parent (a host seen only in a
start URL gets its Subdomain, unverified), history alone is at most high, and
none is an agent lead. Fixture names are example.test only.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        result.__iter__ = lambda s: iter([])
        return result


class _Writer(OsintMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


def _finding(**kw):
    base = {"type": "leaked_one_time_link", "kind": "password_reset", "kind_field": "link_kind",
            "host": "auth.example.test", "path": "/reset", "url": "https://auth.example.test/reset?token=***",
            "severity": "high", "name": "Leaked password-reset link", "first_seen": "2026-09-01",
            "last_seen": "2026-10-01", "props": {"link_count": 3}}
    base.update(kw)
    return base


def _write(findings=(), secrets=(), uid="u1", pid="p1"):
    w = _Writer()
    recon = {"domain": "example.test", "domains": ["example.test"],
             "urlscan": {"findings": list(findings), "url_secrets": list(secrets)}}
    w.update_graph_from_urlscan_findings(recon, uid, pid)
    return w


def _vuln_writes(w):
    return [(q, p) for q, p in w.session.calls if "MERGE (v:Vulnerability" in q]


class TestIds(unittest.TestCase):
    def test_same_finding_two_projects_two_ids_same_project_same_id(self):
        a = _vuln_writes(_write([_finding()], pid="p1"))[0][1]["id"]
        b = _vuln_writes(_write([_finding()], pid="p2"))[0][1]["id"]
        again = _vuln_writes(_write([_finding()], pid="p1"))[0][1]["id"]
        self.assertNotEqual(a, b)
        self.assertEqual(a, again)

    def test_kind_is_part_of_the_id(self):
        reset = _vuln_writes(_write([_finding()]))[0][1]["id"]
        invite = _vuln_writes(_write([_finding(kind="invite")]))[0][1]["id"]
        self.assertNotEqual(reset, invite)

    def test_a_new_token_of_the_same_kind_is_the_same_finding(self):
        a = _vuln_writes(_write([_finding(path="/reset/{token}", url="https://auth.example.test/reset/{token}")]))
        b = _vuln_writes(_write([_finding(path="/reset/{token}", url="https://auth.example.test/reset/{token}",
                                          last_seen="2026-11-01")]))
        self.assertEqual(a[0][1]["id"], b[0][1]["id"])


class TestShape(unittest.TestCase):
    def test_props_name_matched_at_kind_and_tenant(self):
        w = _write([_finding()])
        (q, p), = _vuln_writes(w)
        self.assertIn("MERGE (v:Vulnerability {id: $id, user_id: $uid, project_id: $pid})", q)
        self.assertIn("ON CREATE SET v.source = 'urlscan_leak'", q)
        props = p["props"]
        self.assertEqual(props["link_kind"], "password_reset")
        self.assertEqual(props["matched_at"], "https://auth.example.test/reset?token=***")
        self.assertEqual(props["name"], "Leaked password-reset link")
        self.assertNotIn("needs_agent_confirmation", props)
        self.assertNotIn("urlscan_scan_id", props)

    def test_history_alone_is_at_most_high(self):
        props = _vuln_writes(_write([_finding(severity="critical")]))[0][1]["props"]
        self.assertEqual(props["severity"], "high")
        live = _vuln_writes(_write([_finding(severity="critical", live=True)]))[0][1]["props"]
        self.assertEqual(live["severity"], "critical")

    def test_a_host_only_seen_in_a_start_url_gets_its_subdomain(self):
        w = _write([_finding(host="new.example.test")])
        parent = next(q for q, p in w.session.calls if "HAS_VULNERABILITY" in q and "Subdomain" in q)
        self.assertIn("ON CREATE SET s.source = 'urlscan'", parent)
        self.assertIn("s.status = 'unverified'", parent)

    def test_the_org_name_hangs_off_its_domain(self):
        w = _write([_finding(host="example.test")])
        parent = next(q for q, p in w.session.calls if "HAS_VULNERABILITY" in q and "MERGE (d)" in q)
        self.assertNotIn("Subdomain", parent)

    def test_an_out_of_scope_host_is_not_written(self):
        w = _write([_finding(host="other.test")])
        self.assertTrue(any("WHERE NOT (v)--() DELETE v" in q for q, _p in w.session.calls))
        self.assertFalse([q for q, _p in w.session.calls if "HAS_VULNERABILITY" in q])


class TestProblemAndTakeoverPages(unittest.TestCase):
    """Item 5: problem pages ride with GROUP 1's call; the takeover verdict,
    decided after httpx, is a second call that writes only its own list."""

    PROBLEM = {"type": "open_console_seen", "kind": "jupyter_notebook_open", "kind_field": "problem",
               "host": "nb.example.test", "path": "/tree", "url": "https://nb.example.test/tree",
               "severity": "critical", "name": "Jupyter Notebook seen on urlscan",
               "props": {"family": "open_console", "matched": "Home Page - Select or create a notebook"}}
    TAKEOVER = {"type": "takeover_page_seen", "kind": "heroku", "kind_field": "provider",
                "host": "gone.example.test", "path": "/", "url": "https://gone.example.test/",
                "severity": "medium", "live": True, "name": "Heroku deleted-service page",
                "props": {"outcome": "possible_takeover", "cname": "acme.herokuapp.com",
                          "cname_still_points": True, "verdict_basis": "live_page"}}

    def _writer_run(self, method, **lists):
        w = _Writer()
        recon = {"domain": "example.test", "domains": ["example.test"],
                 "urlscan": {"url_secrets": [TestSecrets.SECRET], **lists}}
        getattr(w, method)(recon, "u1", "p1")
        return w

    def test_group_1_writes_problem_pages_capped_at_high(self):
        w = self._writer_run("update_graph_from_urlscan_findings", problem_pages=[self.PROBLEM],
                             takeover_findings=[self.TAKEOVER])
        (q, p), = _vuln_writes(w)
        self.assertEqual((p["props"]["type"], p["props"]["problem"], p["props"]["severity"]),
                         ("open_console_seen", "jupyter_notebook_open", "high"))
        self.assertEqual(p["props"]["family"], "open_console")

    def test_the_takeover_call_writes_only_its_list(self):
        w = self._writer_run("update_graph_from_urlscan_takeover", problem_pages=[self.PROBLEM],
                             takeover_findings=[self.TAKEOVER])
        (q, p), = _vuln_writes(w)
        self.assertEqual((p["props"]["type"], p["props"]["provider"], p["props"]["outcome"]),
                         ("takeover_page_seen", "heroku", "possible_takeover"))
        self.assertTrue(p["props"]["cname_still_points"])
        self.assertFalse([c for c, _p in w.session.calls if "MERGE (s:Secret" in c])
        self.assertFalse([c for c, _p in w.session.calls if "DETACH DELETE" in c or "prune" in c.lower()])


class TestSecrets(unittest.TestCase):
    SECRET = {"secret_type": "api_key", "param_name": "apikey", "host": "app.example.test",
              "base_url": "https://app.example.test", "value_length": 32, "value_hmac": "ab" * 32,
              "masked_url": "https://app.example.test/api?apikey=***", "severity": "high"}

    def _secret_write(self, w):
        return next((q, p) for q, p in w.session.calls if "MERGE (s:Secret" in q)

    def test_one_secret_per_value_hmac(self):
        a = self._secret_write(_write(secrets=[self.SECRET]))[1]["id"]
        b = self._secret_write(_write(secrets=[dict(self.SECRET, value_hmac="cd" * 32)]))[1]["id"]
        self.assertNotEqual(a, b)

    def test_without_an_hmac_one_secret_per_host_type_and_parameter(self):
        s = {k: v for k, v in self.SECRET.items() if k != "value_hmac"}
        a = self._secret_write(_write(secrets=[s]))[1]
        b = self._secret_write(_write(secrets=[dict(s, value_length=40)]))[1]
        self.assertEqual(a["id"], b["id"])
        self.assertNotIn("value_hmac", a["props"])

    def test_hangs_off_the_subdomain_with_its_base_url(self):
        w = _write(secrets=[self.SECRET])
        q, p = self._secret_write(w)
        self.assertIn("ON CREATE SET s.source = 'urlscan'", q)
        self.assertEqual(p["props"]["base_url"], "https://app.example.test")
        parent = next(q for q, _p in w.session.calls if "HAS_SECRET" in q)
        self.assertIn("Subdomain", parent)
        self.assertFalse([q for q, _p in w.session.calls if "BaseURL" in q and "HAS_SECRET" in q])


class TestWiring(unittest.TestCase):
    def test_full_run_queues_it_with_discovery_outside_httpx(self):
        src = open(os.path.join(_REPO, "recon", "main.py")).read()
        disc = src.index('_graph_update_bg("update_graph_from_urlscan_discovery"')
        find = src.index('_graph_update_bg("update_graph_from_urlscan_findings"')
        self.assertLess(disc, find)
        self.assertLess(find - disc, 400)
        self.assertLess(find, src.index("GROUP 4: HTTP Probing", disc))

    def test_partial_urlscan_calls_it(self):
        src = open(os.path.join(_REPO, "recon", "partial_recon_modules", "osint_enrichment.py")).read()
        self.assertIn("update_graph_from_urlscan_findings", src)

    def test_prune_sources(self):
        # By path: the recon helpers package pulls recon-image dependencies.
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "finding_sources", os.path.join(_REPO, "recon", "helpers", "finding_sources.py"))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.assertIn("urlscan_leak", mod.RECON_FINDING_SOURCES)
        self.assertIn("urlscan", mod.RECON_FINDING_SOURCES)


if __name__ == "__main__":
    unittest.main()
