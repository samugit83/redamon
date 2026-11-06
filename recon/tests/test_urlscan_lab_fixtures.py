"""The urlscan lab's fake urlscan: its fixtures answer in urlscan's format, and its
query language behaves like urlscan's (plan §10.1, §10.4).

gen_lab.py's builder runs into a temporary folder (no openssl, no network), every
fixture is rendered through fake_urlscan/server.py's own response code and
validated against fake_urlscan/urlscan_search.schema.json. The evaluator, the
paging and the control API are driven as plain functions: no socket is opened.
The lab lives in testing/ (no package), so its modules are loaded by file path,
with sys.path and sys.modules restored afterwards.
"""
from __future__ import annotations

import importlib.util
import json
import random
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest import mock
from urllib.parse import quote

LAB = Path(__file__).resolve().parents[2] / "testing" / "guinea_pigs" / "urlscan_lab"


def _load(name: str, rel: str):
    path = LAB / rel
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    # run_lab.py and validate_urlscan_lab.py put their folder on sys.path and
    # import labkit; neither may outlive the load. The module itself is
    # registered only while it executes: dataclasses looks it up there.
    with mock.patch.object(sys, "path", list(sys.path)), mock.patch.dict(sys.modules):
        sys.modules[name] = module
        spec.loader.exec_module(module)
    return module


server = _load("uslab_server", "fake_urlscan/server.py")
schema_check = _load("uslab_schema_check", "fake_urlscan/schema_check.py")
check_fixtures = _load("uslab_check_fixtures", "fake_urlscan/check_fixtures.py")
gen_lab = _load("uslab_gen_lab", "gen_lab.py")
labkit = _load("uslab_labkit", "labkit.py")

SCHEMA = schema_check.load_schema()
LAB_START = datetime(2026, 11, 6, 12, 0, 0, tzinfo=timezone.utc)
LAB_ONLY = {"age_days", "touched_domains", "files", "lab_id", "group", "lab_expect"}

# Every ID of the plan's §11 matrix: expected_results.yaml must hold a block for each.
MATRIX_IDS = [
    "L-01", "L-02", "L-03", "S-01", "S-02", "S-03", "S-04", "S-05", "S-06", "S-07", "S-08", "S-09",
    "S-10", "S-11", "L-04", "D-01",
    "I1-01", "I1-02", "I1-03", "I1-04", "I1-05", "I1-06", "I2-01", "I2-02", "I2-03",
    "I3-01", "I3-02", "I3-03", "I3-04", "I4-01", "I4-02", "I4-03", "I4-04",
    "I5-01", "I5-02", "I5-03", "I5-04", "I5-05", "I5-06", "I5-07",
    "I7-01", "I7-02", "I7-03", "I7-04", "I7-05", "I7-06", "I7-07", "I7-08",
    "B01", "B02", "B03", "B04, B05", "B06", "B07", "B10, B15", "B11", "B12", "B13, B17", "B14", "B16",
    "B19", "B20-B24", "B26", "B27, F1", "B28, F2", "B29, F3, B35", "B30", "B36",
    "U-01", "U-02", "U-03", "U-04", "U-05", "M-01", "M-02", "M-03", "M-04", "M-05",
]


def _visit(lab_id: str, page_domain: str, *, age: float = 1.0, task_domain: str | None = None,
           tags=None, files=(), touched=(), redirected: str | None = None, rnd=None) -> dict:
    rnd = rnd or random.Random(lab_id)
    task_domain = task_domain or page_domain
    task = {"visibility": "public", "method": "api", "domain": task_domain,
            "apexDomain": ".".join(task_domain.split(".")[-2:]),
            "uuid": "%08x-%04x-4%03x-a%03x-%012x" % (rnd.getrandbits(32), rnd.getrandbits(16),
                                                   rnd.getrandbits(12), rnd.getrandbits(12), rnd.getrandbits(48)),
            "url": f"https://{task_domain}/"}
    if tags:
        task["tags"] = list(tags)
    page = {"url": f"https://{page_domain}/", "domain": page_domain,
            "apexDomain": ".".join(page_domain.split(".")[-2:]), "status": "200", "title": lab_id}
    if redirected:
        page["redirected"] = redirected
    return {"submitter": {}, "task": task, "page": page, "labels": [], "age_days": age,
            "touched_domains": list(touched), "files": list(files), "lab_id": lab_id}


def _search(visits, q, *, size=100, after=None, keyed=False):
    return server.run_search(visits, q, size, after, keyed, LAB_START, "http://192.88.97.30")


def _ids(body) -> set[str]:
    return {r["page"]["title"] for r in body["results"]}


class GeneratedFixturesAreUrlscanShaped(unittest.TestCase):
    """The fixtures gen_lab.py writes, rendered by the fake's own code."""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.out = Path(cls.tmp.name) / "generated"
        cls.lab = gen_lab.write_lab(cls.out, certs=False, rnd=random.Random(20261106))
        cls.visits = server.load_visits(str(cls.out / "fixtures" / "visits.json"))
        cls.meta = json.loads((cls.out / "lab.json").read_text())
        cls.tokens = json.loads((cls.out / "tokens.json").read_text())
        cls.by_id = {v["lab_id"]: v for v in cls.visits}

    @classmethod
    def tearDownClass(cls):
        cls.tmp.cleanup()

    def test_check_fixtures_finds_no_problem(self):
        self.assertEqual(check_fixtures.check(self.visits, self.meta), [])

    def test_every_fixture_validates_against_the_schema_keyed_and_not(self):
        for v in self.visits:
            for keyed in (False, True):
                body = {"results": [server.render(v, LAB_START, keyed, "http://192.88.97.30")],
                        "total": 1, "took": 1, "has_more": False}
                with self.subTest(visit=v["lab_id"], keyed=keyed):
                    self.assertEqual(schema_check.check_search(body, SCHEMA), [])
                    self.assertFalse(LAB_ONLY & set(body["results"][0]))
                    self.assertIsInstance(body["results"][0]["page"]["status"], str)

    def test_the_anonymous_main_search_sees_250_visits_in_three_pages(self):
        state = server.LabState(self.visits, lab_start=LAB_START, clock=lambda: 0.0)
        sizes, after, totals = [], None, set()
        for _ in range(10):
            qs = "q=" + quote("page.domain:uslab.test") + "&size=1000" + (f"&search_after={after}" if after else "")
            status, headers, body = state.handle_search(qs, None, "test")
            self.assertEqual(status, 200)
            self.assertEqual(body["search_date_limit_days"], 30)
            self.assertFalse(body["has_more"])
            totals.add(body["total"])
            sizes.append(len(body["results"]))
            if len(body["results"]) < 100:
                break
            after = ",".join(map(str, body["results"][-1]["sort"]))
        self.assertEqual(sizes, [100, 100, 50])
        self.assertEqual(totals, {250})
        self.assertEqual(self.meta["anonymous_visible"], 250)
        self.assertEqual([e["search_after"] is not None for e in state.log], [False, True, True])

    def test_a_key_sees_the_old_origin_visit_in_one_page(self):
        status, body = _search(self.visits, "page.domain:uslab.test", size=10000, keyed=True)
        self.assertEqual(status, 200)
        urls = {(r["page"]["domain"], r["page"]["ip"]) for r in body["results"]}
        self.assertIn(("www.uslab.test", "192.88.97.41"), urls)
        self.assertNotIn("search_date_limit_days", body)
        status, anon = _search(self.visits, "page.domain:uslab.test", size=100)
        self.assertNotIn(("www.uslab.test", "192.88.97.41"),
                         {(r["page"]["domain"], r["page"]["ip"]) for r in anon["results"]})

    def test_the_redirect_search_returns_only_visits_that_left_the_target(self):
        status, body = _search(self.visits, "task.apexDomain:uslab.test AND NOT page.apexDomain:uslab.test")
        self.assertEqual(status, 200)
        found = {self._lab_id(r) for r in body["results"]}
        self.assertEqual(found, {"redir-go", "redir-oauth"})
        for r in body["results"]:
            self.assertEqual(r["page"]["redirected"], "off-domain")

    def test_hash_and_filename_searches(self):
        www, shop = self.meta["bundles"]["www"], self.meta["bundles"]["shop"]
        _, body = _search(self.visits, f"hash:{www['sha256']}")
        found = {self._lab_id(r) for r in body["results"]}
        self.assertTrue({"samefile-bareip", "samefile-mirror", "www-edge-1"} <= found)
        self.assertNotIn("www-origin-old", found)
        _, keyed = _search(self.visits, f"hash:{www['sha256']}", keyed=True)
        self.assertIn("www-origin-old", {self._lab_id(r) for r in keyed["results"]})
        _, by_name = _search(self.visits, f'filename:"{www["name"]}"')
        self.assertEqual({self._lab_id(r) for r in by_name["results"]}, found)
        _, shared = _search(self.visits, f"hash:{shop['sha256']}")
        apexes = {r["page"]["apexDomain"] for r in shared["results"]} - {"uslab.test"}
        self.assertGreater(len({a for a in apexes if not a[0].isdigit()}), 5)
        self.assertIn("shared-bareip", {self._lab_id(r) for r in shared["results"]})

    def _lab_id(self, rendered: dict) -> str:
        return next(v["lab_id"] for v in self.visits if v["task"]["uuid"] == rendered["task"]["uuid"])

    def test_planted_tokens_appear_only_in_their_leak_visits(self):
        hashes = json.loads((self.out / "token_hashes.json").read_text())
        self.assertEqual(sorted(self.tokens), sorted(gen_lab.TOKEN_LABELS))
        for label, value in self.tokens.items():
            with self.subTest(token=label):
                holders = [v["lab_id"] for v in self.visits if value in json.dumps(v)]
                self.assertEqual(holders, [f"leak-{label}"])
                self.assertEqual(hashes[label]["length"], len(value))
                self.assertNotIn(value, (self.out / "token_hashes.json").read_text())
                self.assertNotIn(value, (self.out / "lab.json").read_text())

    def test_tokens_are_token_like_and_jwts_decode(self):
        import base64
        for label in ("T1", "T2", "T3", "T4", "K1"):
            value = self.tokens[label]
            self.assertGreaterEqual(len(value), 16)
            self.assertTrue(any(c.isdigit() for c in value) and any(c.isalpha() for c in value))
        exps = {}
        for label in ("J1", "J2"):
            header, payload, _sig = self.tokens[label].split(".")
            pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
            self.assertEqual(json.loads(base64.urlsafe_b64decode(pad(header)))["alg"], "HS256")
            exps[label] = json.loads(base64.urlsafe_b64decode(pad(payload)))["exp"]
        self.assertLess(exps["J1"], exps["J2"])

    def test_no_site_page_carries_a_token_or_links_a_planted_path(self):
        sites = gen_lab.build_sites(gen_lab.js_bundles())
        text = json.dumps(sites)
        for value in self.tokens.values():
            self.assertNotIn(value, text)
        for site in sites.values():
            for vhost in site["vhosts"]:
                for route in vhost["routes"]:
                    body = route.get("body", "")
                    for planted in ("/reset", "/invite/", "/unsubscribe", "shell.php", ".env", ".git/",
                                    "/auth/magic/", "backup.sql", "heapdump", "/api/data"):
                        self.assertNotIn(f'href="{planted}', body)
                        self.assertNotIn(f"href=\"/{planted.lstrip('/')}", body)

    def test_the_served_bundles_are_what_the_fixtures_fingerprint(self):
        import hashlib
        bundles = gen_lab.js_bundles()
        sites = json.loads((self.out / "sites" / "origin" / "site.json").read_text())
        served = {r["path"]: r["body"] for vh in sites["vhosts"] for r in vh["routes"]}
        for key in ("www", "shop"):
            body = served[bundles[key]["path"]]
            self.assertEqual(hashlib.sha256(body.encode()).hexdigest(), self.meta["bundles"][key]["sha256"])
            self.assertRegex(bundles[key]["name"], r"^(app|main)\.[0-9a-f]{10}\.js$")

    def test_page_signals_check_is_silent_without_the_catalog(self):
        self.assertEqual(gen_lab.check_page_signals(self.visits, Path(self.tmp.name) / "absent.py"), [])

    def test_page_signals_check_reports_a_catalog_that_disagrees(self):
        fake = Path(self.tmp.name) / "page_signals.py"
        fake.write_text("def match_page(title, server, status, path, mime_type):\n    return None\n")
        problems = gen_lab.check_page_signals(self.visits, fake)
        expected = {v["lab_id"] for v in self.visits
                    if v.get("lab_expect", {}).get("match") and not v["lab_expect"].get("certificate")}
        self.assertTrue(expected)
        self.assertEqual({p.split(":", 1)[0] for p in problems}, expected)

    def test_the_real_catalog_agrees_with_every_problem_page_fixture(self):
        # recon/helpers/page_signals.py exists now: a disagreement, or a catalog
        # that fails to load (a dataclass loaded by path needs sys.modules), is
        # a fixture or a rule to fix, never a silent pass.
        self.assertTrue(gen_lab.PAGE_SIGNALS.is_file())
        self.assertEqual(gen_lab.check_page_signals(self.visits), [])

    def test_takeover_cnames_only_with_the_takeover_switch(self):
        gen_lab.compose_dns(self.out, takeover=False)
        self.assertNotIn("CNAME", (self.out / "dns" / "uslab.test.db").read_text())
        gen_lab.compose_dns(self.out, takeover=True)
        zone = (self.out / "dns" / "uslab.test.db").read_text()
        self.assertIn("brokenapp-cname     IN CNAME brokenapp.herokuapp.com.", zone)
        gen_lab.compose_dns(self.out, takeover=False)
        self.assertNotIn("CNAME", (self.out / "dns" / "uslab.test.db").read_text())


class QueryLanguage(unittest.TestCase):
    """The subset of urlscan's query language RedAmon sends (§10.4)."""

    def setUp(self):
        self.visits = [
            _visit("apex", "uslab.test"),
            _visit("app", "app.uslab.test", files=[{"name": "/assets/app.0a1b2c3d4e.js", "sha256": "ab" * 32}]),
            _visit("deep", "x.api.uslab.test", tags=["phishing"]),
            _visit("lookalike", "notuslab.test"),
            _visit("suffix", "uslab.test.evil.test"),
            _visit("redirect", "outsider.uslab-other.test", task_domain="app.uslab.test", redirected="off-domain"),
            _visit("touched", "mirror.uslab-other.test", touched=["cdn.uslab.test"]),
            _visit("old", "old.uslab.test", age=45),
        ]

    def test_page_domain_matches_the_domain_and_every_subdomain_only(self):
        _, body = _search(self.visits, "page.domain:uslab.test")
        self.assertEqual(_ids(body), {"apex", "app", "deep"})

    def test_domain_also_matches_a_domain_the_visit_touched(self):
        _, body = _search(self.visits, "domain:cdn.uslab.test")
        self.assertEqual(_ids(body), {"touched"})

    def test_apex_fields_match_exactly(self):
        _, body = _search(self.visits, "task.apexDomain:uslab.test AND NOT page.apexDomain:uslab.test")
        self.assertEqual(_ids(body), {"redirect"})

    def test_boolean_operators_precedence_and_parentheses(self):
        q = "page.domain:notuslab.test OR page.domain:uslab.test AND task.tags:phishing"
        self.assertEqual(_ids(_search(self.visits, q)[1]), {"lookalike", "deep"})
        q = "(page.domain:notuslab.test OR page.domain:uslab.test) AND NOT task.tags:phishing"
        self.assertEqual(_ids(_search(self.visits, q)[1]), {"lookalike", "apex", "app"})
        q = "page.domain:uslab.test task.tags:phishing"
        self.assertEqual(_ids(_search(self.visits, q)[1]), {"deep"})
        self.assertEqual(_ids(_search(self.visits, "page.redirected:off-domain")[1]), {"redirect"})

    def test_quoted_filename_and_hash(self):
        self.assertEqual(_ids(_search(self.visits, 'filename:"app.0a1b2c3d4e.js"')[1]), {"app"})
        self.assertEqual(_ids(_search(self.visits, "hash:" + "AB" * 32)[1]), {"app"})
        self.assertEqual(_ids(_search(self.visits, "hash:" + "cd" * 32)[1]), set())

    def test_an_unknown_field_or_a_bad_query_is_a_400_in_urlscans_error_shape(self):
        for q in ("page.foo:bar", "justtext", "(page.domain:uslab.test", "page.domain:", "AND page.domain:x", ""):
            with self.subTest(q=q):
                status, body = _search(self.visits, q)
                self.assertEqual(status, 400)
                self.assertEqual(schema_check.check_error(body, SCHEMA), [])

    def test_a_leading_wildcard_or_a_regex_needs_a_key(self):
        for q in ("page.domain:*.uslab.test", "page.domain:/.*uslab.*/", "page.domain:uslab.test OR domain:?x.test"):
            with self.subTest(q=q):
                status, body = _search(self.visits, q)
                self.assertEqual(status, 403)
                self.assertEqual(body["message"], server.FORBIDDEN_MESSAGE)
                self.assertEqual(schema_check.check_error(body, SCHEMA), [])
        status, body = _search(self.visits, "page.domain:*.uslab.test", keyed=True)
        self.assertEqual(status, 200)
        self.assertEqual(_ids(body), {"app", "deep", "old"})
        status, body = _search(self.visits, "page.domain:/.*\\.api\\.uslab\\.test/", keyed=True)
        self.assertEqual((status, _ids(body)), (200, {"deep"}))

    def test_without_a_key_only_the_last_30_days(self):
        self.assertNotIn("old", _ids(_search(self.visits, "page.domain:old.uslab.test")[1]))
        self.assertIn("old", _ids(_search(self.visits, "page.domain:old.uslab.test", keyed=True)[1]))

    def test_at_most_100_results_without_a_key_whatever_size_asks(self):
        many = [_visit(f"v{i}", f"h{i}.uslab.test", age=1 + i / 1000) for i in range(1500)]
        for size in (1000, 10000):
            status, body = _search(many, "page.domain:uslab.test", size=size)
            self.assertEqual((status, len(body["results"]), body["total"]), (200, 100, 1500))
        status, body = _search(many, "page.domain:uslab.test", size=10000, keyed=True)
        self.assertEqual(len(body["results"]), server.KEYED_PAGE_CAP)
        status, body = _search(many, "page.domain:uslab.test", size=250, keyed=True)
        self.assertEqual(len(body["results"]), 250)

    def test_has_more_only_above_ten_thousand(self):
        many = [_visit(f"v{i}", f"h{i}.uslab.test", age=1 + i / 100000) for i in range(10_001)]
        _, body = _search(many[:10_000], "page.domain:uslab.test")
        self.assertEqual((body["total"], body["has_more"]), (10_000, False))
        _, body = _search(many, "page.domain:uslab.test")
        self.assertEqual((body["total"], body["has_more"]), (10_000, True))
        _, body = _search(many[:2696], "page.domain:uslab.test")
        self.assertEqual((body["total"], body["has_more"], len(body["results"])), (2696, False, 100))

    def test_search_after_returns_the_next_older_page(self):
        many = [_visit(f"v{i}", f"h{i}.uslab.test", age=1 + i / 100) for i in range(230)]
        seen, after, pages = [], None, 0
        while True:
            status, body = _search(many, "page.domain:uslab.test", after=after)
            self.assertEqual(status, 200)
            pages += 1
            sorts = [tuple(r["sort"]) for r in body["results"]]
            self.assertEqual(sorts, sorted(sorts, reverse=True))
            if seen and sorts:
                self.assertLess(sorts[0], seen[-1])
            seen += sorts
            if len(body["results"]) < 100:
                break
            after = f"{sorts[-1][0]},{sorts[-1][1]}"
        self.assertEqual((pages, len(seen), len(set(seen))), (3, 230, 230))
        self.assertEqual(_search(many, "page.domain:uslab.test", after="nonsense")[0], 400)

    def test_rendered_result_follows_the_captured_shape(self):
        v = _visit("tls", "tls.uslab.test", age=2.5)
        v["page"].update({"tlsIssuer": "Lab Issuing CA 1", "tlsValidDays": 90, "tlsAgeDays": 40})
        v["verdicts"] = {"overall": {"malicious": False}}
        anon = server.render(v, LAB_START, False, "http://192.88.97.30")
        keyed = server.render(v, LAB_START, True, "http://192.88.97.30")
        self.assertEqual(anon["_id"], anon["task"]["uuid"])
        self.assertEqual(anon["sort"][1], anon["task"]["uuid"])
        when = LAB_START - timedelta(days=2.5)
        self.assertEqual(anon["sort"][0], int(when.timestamp() * 1000))
        self.assertTrue(anon["task"]["time"].endswith("Z"))
        self.assertEqual(anon["page"]["tlsValidFrom"][:10], (when - timedelta(days=40)).strftime("%Y-%m-%d"))
        self.assertNotIn("verdicts", anon)
        self.assertIn("verdicts", keyed)
        self.assertIsNone(anon["_score"])
        self.assertFalse(LAB_ONLY & set(anon))


class LabControl(unittest.TestCase):
    """Forced failures, the rate-limit headers, the key handling and the log."""

    def setUp(self):
        self.now = [1_000_000.0]
        self.state = server.LabState([_visit("apex", "uslab.test")], lab_start=LAB_START,
                                     clock=lambda: self.now[0], lab_key="lab-key")

    def _q(self, q="page.domain:uslab.test", extra=""):
        return "q=" + quote(q) + extra

    def test_every_answer_carries_the_rate_limit_headers(self):
        status, headers, _ = self.state.handle_search(self._q(), None, "1.2.3.4")
        self.assertEqual(status, 200)
        for name in ("x-rate-limit-scope", "x-rate-limit-action", "x-rate-limit-window", "x-rate-limit-limit",
                     "x-rate-limit-remaining", "x-rate-limit-reset", "x-rate-limit-reset-after",
                     "x-rate-limit-concurrency-rank", "x-rate-limit-concurrency-limit"):
            self.assertIn(name, headers)
        self.assertEqual((headers["x-rate-limit-limit"], headers["x-rate-limit-remaining"]), ("30", "29"))
        self.assertEqual(headers["x-rate-limit-scope"], "ip-address")
        self.assertRegex(headers["x-rate-limit-reset"], r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:00\.000Z$")

    def test_the_31st_anonymous_search_in_a_minute_is_a_429_with_retry_after(self):
        for _ in range(30):
            self.assertEqual(self.state.handle_search(self._q(), None, "ip")[0], 200)
        status, headers, body = self.state.handle_search(self._q(), None, "ip")
        self.assertEqual(status, 429)
        self.assertIn("Retry-After", headers)
        self.assertEqual(schema_check.check_error(body, SCHEMA), [])
        self.now[0] += 60
        self.assertEqual(self.state.handle_search(self._q(), None, "ip")[0], 200)

    def test_a_fail_rule_answers_its_status_the_given_number_of_times(self):
        self.state.add_fail({"query_regex": r"^page\.domain:", "status": 429, "times": 2})
        statuses = [self.state.handle_search(self._q(), None, "ip")[0] for _ in range(3)]
        self.assertEqual(statuses, [429, 429, 200])
        self.state.add_fail({"query_regex": "apexDomain", "status": 400, "times": 1})
        self.assertEqual(self.state.handle_search(self._q(), None, "ip")[0], 200)
        self.assertEqual(self.state.handle_search(self._q("task.apexDomain:uslab.test"), None, "ip")[0], 400)
        self.state.add_fail({"query_regex": ".", "status": 403, "times": 1})
        status, _h, body = self.state.handle_search(self._q(), None, "ip")
        self.assertEqual((status, body["message"]), (403, server.FORBIDDEN_MESSAGE))
        with self.assertRaises(ValueError):
            self.state.add_fail({"query_regex": ".", "status": 500})

    def test_a_fail_rule_can_hit_only_the_later_pages(self):
        self.state.add_fail({"query_regex": ".", "status": 429, "times": 5, "search_after": True})
        self.assertEqual(self.state.handle_search(self._q(), None, "ip")[0], 200)
        self.assertEqual(self.state.handle_search(self._q(extra="&search_after=1,abc"), None, "ip")[0], 429)

    def test_the_lab_key_is_keyed_mode_any_other_key_is_refused_and_no_value_is_logged(self):
        status, headers, body = self.state.handle_search(self._q("page.domain:*.uslab.test"), "lab-key", "ip")
        self.assertEqual(status, 200)
        self.assertNotIn("search_date_limit_days", body)
        self.assertEqual(headers["x-rate-limit-scope"], "user")
        status, _h, _b = self.state.handle_search(self._q(), "a-real-looking-key-1234", "ip")
        self.assertEqual(status, 401)
        log = json.dumps(self.state.log)
        self.assertNotIn("lab-key", log)
        self.assertNotIn("a-real-looking-key-1234", log)
        self.assertEqual([(e["key_sent"], e["key_is_lab_key"]) for e in self.state.log],
                         [(True, True), (True, False)])

    def test_the_log_records_each_search_and_reset_clears_it(self):
        self.state.handle_search(self._q(extra="&size=7&search_after=5,x"), None, "ip")
        entry = self.state.log[-1]
        self.assertEqual((entry["query"], entry["size"], entry["search_after"], entry["key_sent"]),
                         ("page.domain:uslab.test", "7", "5,x", False))
        self.state.add_fail({"query_regex": ".", "status": 429})
        self.state.reset()
        self.assertEqual((self.state.log, self.state.fail_rules), ([], []))


class SchemaSubset(unittest.TestCase):
    def test_optional_fields_may_be_absent_but_never_null(self):
        body = {"results": [], "total": 0, "took": 0, "has_more": False, "search_date_limit_days": 30}
        self.assertEqual(schema_check.check_search(body, SCHEMA), [])
        item = server.render(_visit("x", "x.uslab.test"), LAB_START, False, "http://192.88.97.30")
        item["page"]["server"] = None
        item["page"]["status"] = 200
        errors = schema_check.check_search({**body, "results": [item]}, SCHEMA)
        self.assertTrue(any("page.server" in e for e in errors))
        self.assertTrue(any("page.status" in e for e in errors))

    def test_an_unsupported_keyword_is_refused_not_ignored(self):
        with self.assertRaises(schema_check.SchemaError):
            schema_check.errors({}, {"type": "object", "additionalProperties": False})

    def test_positional_items(self):
        schema = {"type": "array", "items": [{"type": "integer"}, {"type": "string"}]}
        self.assertEqual(schema_check.errors([1, "a"], schema), [])
        self.assertEqual(len(schema_check.errors(["a", 1], schema)), 2)
        self.assertTrue(schema_check.errors([True, "a"], schema))


class ExpectedResultsCoverTheMatrix(unittest.TestCase):
    """expected_results.yaml: one block per §11 ID, every check of a known kind and run."""

    @classmethod
    def setUpClass(cls):
        cls.rows = labkit.load_yaml((LAB / "expected_results.yaml").read_text())["rows"]
        cls.validator = _load("uslab_validator", "validate_urlscan_lab.py")
        cls.run_lab = _load("uslab_run_lab", "run_lab.py")

    def test_every_matrix_id_has_exactly_one_block(self):
        ids = [r["id"] for r in self.rows]
        self.assertEqual(sorted(ids), sorted(MATRIX_IDS))
        self.assertEqual(len(ids), len(set(ids)))

    def test_every_check_has_a_kind_an_assertion_and_known_runs(self):
        runs = set(self.run_lab.RUNS)
        by_id = {r["id"] for r in self.rows}
        for row in self.rows:
            for check in row["checks"]:
                with self.subTest(row=row["id"], check=check):
                    kind = self.validator.check_kind(check)
                    if kind in ("cypher", "recon_json"):
                        self.assertTrue(any(k in check for k in self.validator.ASSERTIONS))
                    if kind == "cypher":
                        self.assertIn("$pid", check["cypher"])
                    if kind == "see":
                        self.assertTrue(set(check["see"]) <= by_id)
                    if kind in ("hits", "urlscan_log", "scan_log"):
                        spec = check[kind]
                        self.assertTrue(any(k in spec for k in ("count", "min", "max")))
                    named = set(check.get("runs") or row.get("runs") or [])
                    if kind == "compare":
                        named = set(self.validator._compare_runs(check))
                    self.assertTrue(named <= runs, named - runs)

    def test_placeholders_name_only_known_values(self):
        text = (LAB / "expected_results.yaml").read_text()
        values = {**{t: "x" for t in gen_lab.TOKEN_LABELS},
                  **labkit.placeholders({}, {"bundles": {k: {"sha256": "0", "name": "n"}
                                                         for k in ("www", "shop", "decoy")}})}
        labkit.substitute(text, values)

    def test_the_log_side_checks_read_a_run_folder(self):
        with tempfile.TemporaryDirectory() as tmp:
            runs = Path(tmp)
            (runs / "A" / "hits").mkdir(parents=True)
            (runs / "A" / "run.json").write_text(json.dumps({"project_id": "p1"}))
            (runs / "A" / "hits" / "uslab-web.jsonl").write_text("\n".join(json.dumps(e) for e in [
                {"method": "GET", "host": "auth.uslab.test", "uri": "/reset?token=SECRET1x"},
                {"method": "POST", "host": "auth.uslab.test:443", "uri": "/login"},
            ]))
            (runs / "A" / "urlscan_log.json").write_text(json.dumps([
                {"query": "page.domain:uslab.test", "search_after": None, "key_sent": False},
                {"query": "page.domain:uslab.test", "search_after": "1,a", "key_sent": False},
            ]))
            (runs / "A" / "container_env.json").write_text(json.dumps({"hooks": ["URLSCAN_API_BASE"]}))
            values = {"T1": "SECRET1x"}
            with mock.patch.object(self.validator.labkit, "RUNS", runs):
                v = self.validator
                self.assertEqual(v.eval_hits({"uri_regex": "<<T1>>", "count": 0}, "A", values)[0], False)
                self.assertEqual(v.eval_hits({"host": "auth.uslab.test", "method": "POST",
                                              "uri_regex": "^/login", "min": 1}, "A", values)[0], True)
                self.assertTrue(v.eval_urlscan_log({"query_regex": r"^page\.domain:", "search_after": True,
                                                    "count": 1}, "A", values)[0])
                self.assertFalse(v.eval_container_env({"absent": ["URLSCAN_API_BASE"]}, "A")[0])
                detail = v.eval_hits({"uri_regex": "<<T1>>", "count": 0}, "A", values)[1]
                self.assertNotIn("SECRET1x", detail)


if __name__ == "__main__":
    unittest.main()
