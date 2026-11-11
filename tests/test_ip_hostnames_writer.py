"""update_graph_from_ip_hostnames: the names recorded on target IPs (P3, design §6).

A recorded name (any reason but `scanned`) becomes an ExternalDomain under the
mock root, never a Subdomain (invariant I-4), keyed on the tenant triple of
the `externaldomain_unique` constraint. Three statements per batch, each on
its own so a missing mock Domain or IP node never stops the node write:

1. the node: `sources` and `ips_seen` grow additively (the external-domains
   aggregator writes the same node), the `ip_hostname_*` evidence is plain SET;
2. `(mock Domain)-[:HAS_EXTERNAL_DOMAIN]->(ed)`, the aggregator's edge;
3. `(ed)-[:SEEN_ON]->(ip)` per target IP, with that IP's evidence.

Every full IP-mode run, IP only included, also stamps the run's hostname mode
on the mock root (`ip_hostname_mode`), so a reader tells "never ran in a
record mode" from "a record run found no name". The root is MATCHed, never
MERGEd: only the IP-recon writer creates it (tests/test_no_stray_domain_merge.py).

Task 10: the aggregator and this writer on the same redirect name keep both
writers' sources and the `ip_hostname_*` properties in either order. The SET
clauses are read from the real Cypher and applied to an in-memory node.

The Neo4j session is a fake that records each statement. Documentation ranges
and reserved names only.

Run: ./redamon.sh test unit (root-agent section), or one file in the agent image.
"""
import os
import re
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from graph_db.mixins.recon import ip_hostnames_mixin as ihm  # noqa: E402
from graph_db.mixins.recon.ip_hostnames_mixin import IpHostnamesMixin  # noqa: E402

T1, T2 = "203.0.113.10", "203.0.113.11"
UID, PID = "u1", "cmwriter000000000000000001"
MOCK = f"ip-targets.{PID}"


class _Result:
    def __init__(self, n):
        self._n = n

    def single(self):
        return {"n": self._n}


class _Tx:
    def __init__(self, calls, fail_on=None):
        self.calls, self.fail_on = calls, fail_on

    def run(self, query, **params):
        if self.fail_on and self.fail_on in query:
            raise RuntimeError("neo4j says no")
        self.calls.append((query, params))
        rows = params.get("rows") or params.get("seen") or params.get("names") or []
        return _Result(len(rows))


class _Session:
    def __init__(self, fail_on=None):
        self.calls, self.fail_on, self.transactions = [], fail_on, 0

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def execute_write(self, work):
        self.transactions += 1
        return work(_Tx(self.calls, self.fail_on))

    def run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        result.single.return_value = None
        return result


class _Writer(IpHostnamesMixin, OsintMixin):
    def __init__(self, fail_on=None):
        self.session = _Session(fail_on)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def statements(self, marker):
        return [(q, p) for q, p in self.session.calls if marker in q]


def _candidate(ips, reason="record_only", **extra):
    seen = {ip: {"sources": ["ptr"], "first_seen": None, "last_seen": None, "cert_covers": False}
            for ip in ips}
    return {"ips_seen": list(ips), "sources": ["ptr"], "first_seen": None, "last_seen": None,
            "cert_covers": False, "org_domain": "example.com", "on_shared_edge": None,
            "seen_on": seen, "reason": reason, **extra}


def _recon(candidates, ip_mode=True):
    return {"domain": MOCK,
            "metadata": {"ip_mode": ip_mode, "root_domain": MOCK, "expanded_ips": [T1, T2]},
            "ip_hostnames": {"mode": "record_only", "candidates": candidates}}


class TestRecordedNames(unittest.TestCase):
    def setUp(self):
        self.writer = _Writer()
        self.cand = _candidate([T1, T2])
        self.cand["seen_on"][T1] = {"sources": ["otx_passive_dns", "ptr"], "first_seen": "2024-01-01",
                                    "last_seen": "2026-01-01", "cert_covers": True}
        self.stats = self.writer.update_graph_from_ip_hostnames(
            _recon({"web.example.com": self.cand}), UID, PID)

    def test_the_node_is_an_external_domain_on_the_tenant_key(self):
        (query, params), = self.writer.statements("MERGE (ed:ExternalDomain")
        self.assertIn("MERGE (ed:ExternalDomain {domain: row.name, user_id: $uid, project_id: $pid})", query)
        self.assertNotIn("Subdomain", query)
        self.assertEqual((params["uid"], params["pid"]), (UID, PID))
        self.assertEqual(params["rows"], [{"name": "web.example.com", "sources": ["ptr"],
                                           "ips": [T1, T2], "reason": "record_only",
                                           "org": "example.com"}])

    def test_provenance_on_create_lists_additively_evidence_plainly(self):
        (query, _), = self.writer.statements("MERGE (ed:ExternalDomain")
        self.assertIn("ON CREATE SET ed.first_seen_at = datetime()", query)
        self.assertIn("ed.sources = coalesce(ed.sources, []) + "
                      "[x IN row.sources WHERE NOT x IN coalesce(ed.sources, [])]", query)
        self.assertIn("ed.ips_seen = coalesce(ed.ips_seen, []) + "
                      "[x IN row.ips WHERE NOT x IN coalesce(ed.ips_seen, [])]", query)
        for plain in ("ed.ip_hostname_reason = row.reason", "ed.ip_hostname_org = row.org",
                      "ed.ip_hostname_evaluated_at = datetime()", "ed.updated_at = datetime()"):
            self.assertIn(plain, query)

    def test_the_mock_root_links_it_with_the_aggregators_edge(self):
        (query, params), = self.writer.statements("HAS_EXTERNAL_DOMAIN")
        self.assertIn("MATCH (d:Domain {name: $mock, user_id: $uid, project_id: $pid})", query)
        self.assertIn("MATCH (ed:ExternalDomain {domain: name, user_id: $uid, project_id: $pid})", query)
        self.assertIn("MERGE (d)-[:HAS_EXTERNAL_DOMAIN]->(ed)", query)
        self.assertNotIn("MERGE (d:Domain", query)
        self.assertEqual(params["mock"], MOCK)
        self.assertEqual(params["names"], ["web.example.com"])

    def test_seen_on_carries_the_evidence_of_each_target_ip(self):
        (query, params), = self.writer.statements("SEEN_ON")
        self.assertIn("MATCH (i:IP {address: s.ip, user_id: $uid, project_id: $pid})", query)
        self.assertIn("MERGE (ed)-[r:SEEN_ON]->(i)", query)
        self.assertNotIn("MERGE (i:IP", query)
        for prop in ("r.sources = s.sources", "r.first_seen = s.first", "r.last_seen = s.last",
                     "r.resolves_here = s.resolves_here", "r.cert_covers = s.cert_covers",
                     "r.reason = s.reason"):
            self.assertIn(prop, query)
        self.assertEqual(params["seen"], [
            {"name": "web.example.com", "ip": T1, "sources": ["otx_passive_dns", "ptr"],
             "first": "2024-01-01", "last": "2026-01-01", "resolves_here": None,
             "cert_covers": True, "reason": "record_only"},
            {"name": "web.example.com", "ip": T2, "sources": ["ptr"], "first": None, "last": None,
             "resolves_here": None, "cert_covers": False, "reason": "record_only"},
        ])

    def test_the_three_statements_are_separate_in_one_transaction(self):
        self.assertEqual(self.writer.session.transactions, 1)
        names = [q for q, _ in self.writer.session.calls if "ip_hostname_mode" not in q]
        self.assertEqual(len(names), 3)
        node, link, seen = names
        # The node write depends on no MATCH; the link and the evidence match it.
        self.assertNotIn("MATCH", node)
        self.assertIn("HAS_EXTERNAL_DOMAIN", link)
        self.assertIn("SEEN_ON", seen)

    def test_every_merge_and_match_is_tenant_scoped(self):
        for query, _ in self.writer.session.calls:
            for clause in re.findall(r"(?:MERGE|MATCH) \(\w+:\w+ \{[^}]*\}\)", query):
                self.assertIn("user_id: $uid", clause, clause)
                self.assertIn("project_id: $pid", clause, clause)

    def test_stats(self):
        self.assertEqual(self.stats, {"mode_stamped": True, "names_recorded": 1, "names_scanned": 0, "seen_on": 2,
                                      "errors": []})


class TestRunModeOnTheMockRoot(unittest.TestCase):
    def _mode_statements(self, writer):
        return writer.statements("ip_hostname_mode")

    def test_every_run_stamps_its_mode_on_the_mock_root_by_match(self):
        w = _Writer()
        w.update_graph_from_ip_hostnames(_recon({"web.example.com": _candidate([T1])}), UID, PID)
        (query, params), = self._mode_statements(w)
        self.assertIn("MATCH (d:Domain {name: $mock, user_id: $uid, project_id: $pid})", query)
        self.assertIn("WHERE d.is_mock = true", query)
        self.assertIn("SET d.ip_hostname_mode = $mode", query)
        self.assertNotIn("MERGE", query)
        self.assertEqual(params, {"mock": MOCK, "uid": UID, "pid": PID, "mode": "record_only"})

    def test_ip_only_writes_the_mode_and_nothing_name_related(self):
        w = _Writer()
        recon = _recon({})
        recon["ip_hostnames"] = {"mode": "ip_only", "candidates": {}, "by_ip": {}}
        stats = w.update_graph_from_ip_hostnames(recon, UID, PID)
        self.assertEqual([p["mode"] for _, p in self._mode_statements(w)], ["ip_only"])
        self.assertEqual(len(w.session.calls), 1)
        self.assertEqual(w.session.transactions, 0)
        self.assertEqual(stats, {"mode_stamped": True, "names_recorded": 0, "names_scanned": 0, "seen_on": 0,
                                 "errors": []})

    def test_a_block_without_a_mode_stamps_nothing(self):
        w = _Writer()
        recon = _recon({"web.example.com": _candidate([T1])})
        del recon["ip_hostnames"]["mode"]
        stats = w.update_graph_from_ip_hostnames(recon, UID, PID)
        self.assertEqual(self._mode_statements(w), [])
        self.assertFalse(stats["mode_stamped"])
        self.assertEqual(stats["names_recorded"], 1)

    def test_a_failed_stamp_is_reported_and_the_names_are_still_written(self):
        w = _Writer()
        w.session.run = MagicMock(side_effect=RuntimeError("neo4j says no"))
        stats = w.update_graph_from_ip_hostnames(_recon({"web.example.com": _candidate([T1])}), UID, PID)
        self.assertFalse(stats["mode_stamped"])
        self.assertEqual(stats["names_recorded"], 1)
        self.assertIn("ip_hostname_mode", stats["errors"][0])


class TestWhatIsWritten(unittest.TestCase):
    def test_resolves_here_is_per_ip_once_the_name_was_resolved(self):
        w = _Writer()
        cand = _candidate([T1, T2], resolves_to_now=[T1])
        w.update_graph_from_ip_hostnames(_recon({"r.example.com": cand}), UID, PID)
        (_, params), = w.statements("SEEN_ON")
        self.assertEqual([s["resolves_here"] for s in params["seen"]], [True, False])

    def test_a_scanned_or_unexplained_name_is_not_written_as_recorded(self):
        w = _Writer()
        stats = w.update_graph_from_ip_hostnames(_recon({
            "s.example.com": _candidate([T1], reason="scanned"),
            "n.example.com": _candidate([T1], reason=None),
            "bad": "not a candidate",
            "k.example.com": _candidate([T1], reason="hard_blocked"),
        }), UID, PID)
        (_, params), = w.statements("MERGE (ed:ExternalDomain")
        self.assertEqual([r["name"] for r in params["rows"]], ["k.example.com"])
        self.assertEqual(params["rows"][0]["reason"], "hard_blocked")
        self.assertEqual(stats["names_recorded"], 1)

    def test_seen_on_falls_back_to_ips_seen_and_skips_unknown_ips(self):
        w = _Writer()
        cand = _candidate([T1, T2])
        cand["seen_on"] = {T1: "junk"}
        w.update_graph_from_ip_hostnames(_recon({"f.example.com": cand}), UID, PID)
        (_, params), = w.statements("SEEN_ON")
        self.assertEqual([(s["ip"], s["sources"]) for s in params["seen"]],
                         [(T1, ["ptr"]), (T2, ["ptr"])])

    def test_nothing_is_written_outside_ip_mode_or_without_the_hooks_block(self):
        for recon in (_recon({"x.example.com": _candidate([T1])}, ip_mode=False),
                      {"metadata": {"ip_mode": True}}):
            w = _Writer()
            self.assertEqual(w.update_graph_from_ip_hostnames(recon, UID, PID),
                             {"mode_stamped": False, "names_recorded": 0, "names_scanned": 0, "seen_on": 0,
                              "errors": []})
            self.assertEqual(w.session.calls, [])

    def test_a_record_run_without_names_stamps_the_mode_only(self):
        w = _Writer()
        stats = w.update_graph_from_ip_hostnames(_recon({}), UID, PID)
        self.assertEqual(len(w.session.calls), 1)
        self.assertEqual(stats["names_recorded"], 0)

    def test_names_are_written_in_batches(self):
        w = _Writer()
        old = ihm._BATCH
        ihm._BATCH = 2
        try:
            stats = w.update_graph_from_ip_hostnames(_recon(
                {f"n{i}.example.com": _candidate([T1]) for i in range(5)}), UID, PID)
        finally:
            ihm._BATCH = old
        self.assertEqual(w.session.transactions, 3)
        self.assertEqual(stats["names_recorded"], 5)

    def test_a_failed_batch_is_reported_and_the_next_one_still_runs(self):
        w = _Writer(fail_on="SEEN_ON")
        stats = w.update_graph_from_ip_hostnames(_recon({"e.example.com": _candidate([T1])}), UID, PID)
        self.assertEqual(stats["names_recorded"], 0)
        self.assertEqual(len(stats["errors"]), 1)
        self.assertIn("e.example.com", stats["errors"][0])

    def test_the_mock_root_falls_back_to_the_domain_key(self):
        w = _Writer()
        recon = _recon({"m.example.com": _candidate([T1])})
        del recon["metadata"]["root_domain"]
        w.update_graph_from_ip_hostnames(recon, UID, PID)
        (_, params), = w.statements("HAS_EXTERNAL_DOMAIN")
        self.assertEqual(params["mock"], MOCK)


# ---------------------------------------------------------------------------
# Task 10: the external-domains aggregator and this writer on one node
# ---------------------------------------------------------------------------

_ADDITIVE = re.compile(r"coalesce\(ed\.(\w+), \[\]\) \+ \[x IN ([$\w.]+) WHERE NOT x IN coalesce\(ed\.\1, \[\]\)\]")


def _set_clauses(query: str) -> dict:
    """{property: expression} of the `SET ed.x = ...` assignments of the node statement."""
    body = query.split("ON CREATE SET", 1)[-1]
    out = {}
    for prop, expr in re.findall(r"\bed\.(\w+) = (.+?)(?:,\n|\n|$)", body):
        out.setdefault(prop, expr.strip().rstrip(","))
    return out


def _apply(node: dict, query: str, values: dict) -> None:
    """Apply one writer's SET to `node`, as Neo4j would for these two shapes."""
    for prop, expr in _set_clauses(query).items():
        additive = _ADDITIVE.fullmatch(expr)
        if additive:
            new = values[additive.group(2)]
            node[prop] = list(node.get(prop) or []) + [x for x in new if x not in (node.get(prop) or [])]
        elif expr == "datetime()":
            node[prop] = "now"
        elif expr in values:
            node[prop] = values[expr]
        else:
            node.setdefault(prop, f"<{expr}>")


class TestAggregatorAndHookOnOneNode(unittest.TestCase):
    NAME = "moved.example.com"

    def _hook_statement(self):
        w = _Writer()
        cand = _candidate([T1])
        cand["sources"] = ["http_redirect", "ptr"]
        w.update_graph_from_ip_hostnames(_recon({self.NAME: cand}), UID, PID)
        (query, params), = w.statements("MERGE (ed:ExternalDomain")
        row = params["rows"][0]
        return query, {f"row.{k}": v for k, v in row.items()}

    def _aggregator_statement(self):
        w = _Writer()
        w.update_graph_from_external_domains({
            "domain": MOCK, "metadata": {"ip_mode": True, "root_domain": MOCK},
            "external_domains_aggregated": [{
                "domain": self.NAME, "sources": ["http_probe_redirect"],
                "redirect_from_urls": [f"https://{T1}/"], "redirect_to_urls": [f"https://{self.NAME}/"],
                "ips_seen": [], "times_seen": 1}],
        }, UID, PID)
        (query, params), = w.statements("MERGE (ed:ExternalDomain")
        return query, {f"${k}": v for k, v in params.items()}

    def _both(self, first, second):
        node = {}
        for query, values in (first, second):
            _apply(node, query, values)
        return node

    def test_either_order_keeps_both_writers_sources_and_the_hook_evidence(self):
        hook, agg = self._hook_statement(), self._aggregator_statement()
        for order in ((hook, agg), (agg, hook)):
            node = self._both(*order)
            self.assertEqual(sorted(node["sources"]), ["http_probe_redirect", "http_redirect", "ptr"])
            self.assertEqual(node["ips_seen"], [T1])
            self.assertEqual(node["ip_hostname_reason"], "record_only")
            self.assertEqual(node["ip_hostname_org"], "example.com")
            self.assertEqual(node["redirect_from_urls"], [f"https://{T1}/"])

    def test_the_aggregator_never_touches_the_hook_evidence(self):
        agg_query, _ = self._aggregator_statement()
        self.assertNotIn("ip_hostname", agg_query)

    def test_the_hook_never_touches_the_aggregators_redirect_fields(self):
        hook_query, _ = self._hook_statement()
        for prop in ("redirect_from_urls", "redirect_to_urls", "times_seen", "status_codes_seen"):
            self.assertNotIn(prop, hook_query)


# ---------------------------------------------------------------------------
# P4: the scanned part (design §6 "Scanned name", §6.2)
# ---------------------------------------------------------------------------

from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402

APP, SHOP = "app.example.com", "shop.example.net"
FP = "ab" * 32


class _ScannedWriter(IpHostnamesMixin, DomainMixin, OsintMixin):
    """The real allowed Domain site (ensure_root_domains) behind the writer."""

    def __init__(self, fail_on=None):
        self.session = _Session(fail_on)
        self.driver = MagicMock()
        self.driver.session.return_value = self.session

    def statements(self, marker):
        return [(q, p) for q, p in self.session.calls if marker in q]


def _scanned_recon(**extra):
    app = _candidate([T1], reason="scanned", sources=["ptr", "tlsx_san"], resolves_to_now=[T1, "2001:db8::10"])
    app["seen_on"][T1] = {"sources": ["otx_passive_dns", "ptr", "tlsx_san"], "first_seen": "2024-01-01",
                          "last_seen": "2026-01-01", "cert_covers": True}
    shop = _candidate([T2], reason="scanned", org_domain="example.net", resolves_to_now=[T2])
    recorded = _candidate([T1], reason="filter_no_match")
    recon = _recon({APP: app, SHOP: shop, "old.example.com": recorded})
    recon["ip_hostnames"]["mode"] = "record_filter"
    recon["metadata"]["ip_mode_hosts"] = {APP: "example.com", SHOP: "example.net"}
    recon["tlsx"] = {"by_target": {
        f"{T1}:443": {"scanned_ip": T1, "fingerprint_sha256": FP, "subject_cn": "www.example.com",
                      "san_raw": ["www.example.com", "*.example.com"], "san": ["www.example.com", "example.com"]},
        f"{T2}:443": {"scanned_ip": T2, "fingerprint_sha256": "cd" * 32, "subject_cn": "other.test",
                      "san": ["other.test"]},
        f"{T2}:8443": {"scanned_ip": T2},
        "junk": "junk"}}
    recon.update(extra)
    return recon


class TestScannedNames(unittest.TestCase):
    def setUp(self):
        self.writer = _ScannedWriter()
        self.stats = self.writer.update_graph_from_ip_hostnames(_scanned_recon(), UID, PID)

    def test_the_org_domains_come_from_the_allowed_site_then_get_marked(self):
        (seed_q, seed_p), = self.writer.statements("MERGE (d:Domain")
        self.assertIn("MERGE (d:Domain {name: name, user_id: $user_id, project_id: $project_id})", seed_q)
        self.assertEqual(sorted(seed_p["names"]), ["example.com", "example.net"])
        (mark_q, mark_p), = self.writer.statements("ip_hostname_org = true")
        self.assertIn("MATCH (d:Domain {name: org, user_id: $uid, project_id: $pid})", mark_q)
        self.assertNotIn("MERGE (d:Domain", mark_q)
        self.assertEqual(sorted(mark_p["orgs"]), ["example.com", "example.net"])
        # An org Domain is no IP-mode root: every Domain.ip_mode reader keeps
        # treating it as any org (design §6.1).
        for query in (seed_q, mark_q):
            self.assertNotIn("ip_mode", query)
            self.assertNotIn("is_mock", query)

    def test_the_subdomain_carries_the_selection(self):
        (query, params), = self.writer.statements("MERGE (s:Subdomain")
        self.assertIn("MERGE (s:Subdomain {name: row.name, user_id: $uid, project_id: $pid})", query)
        self.assertIn("ON CREATE SET s.source = 'ip_hostname_selection'", query)
        for prop in ("s.ip_mode = true", "s.has_records = true", "s.ip_hostname_reason = 'scanned'",
                     "s.ip_hostname_sources = row.sources", "s.ip_hostname_evaluated_at = datetime()"):
            self.assertIn(prop, query)
        self.assertEqual(params["rows"], [
            {"name": APP, "org": "example.com", "sources": ["ptr", "tlsx_san"]},
            {"name": SHOP, "org": "example.net", "sources": ["ptr"]}])

    def test_it_hangs_off_its_org_domain(self):
        (query, params), = self.writer.statements("HAS_SUBDOMAIN")
        self.assertIn("MATCH (d:Domain {name: row.org, user_id: $uid, project_id: $pid})", query)
        self.assertIn("MERGE (d)-[:HAS_SUBDOMAIN]->(s)", query)
        self.assertIn("MERGE (s)-[:BELONGS_TO]->(d)", query)

    def test_resolves_to_is_the_pinned_answer_and_current_dns(self):
        (query, params), = self.writer.statements("[r:RESOLVES_TO]")
        self.assertIn("MATCH (i:IP {address: e.ip, user_id: $uid, project_id: $pid})", query)
        # Forward DNS just resolved it: no `source`, which marks a passive,
        # not-current edge for every RESOLVES_TO reader (schema_sections.md).
        self.assertIn("REMOVE r.source", query)
        self.assertNotIn("MERGE (i:IP", query)
        self.assertEqual(params["edges"], [
            {"name": APP, "ip": T1, "record_type": "A"},
            {"name": APP, "ip": "2001:db8::10", "record_type": "AAAA"},
            {"name": SHOP, "ip": T2, "record_type": "A"}])

    def test_a_dated_source_writes_the_history_edge(self):
        (query, params), = self.writer.statements("HISTORICALLY_RESOLVED_TO")
        self.assertIn("MERGE (s)-[r:HISTORICALLY_RESOLVED_TO {source: h.source}]->(i)", query)
        self.assertEqual(params["history"], [
            {"name": APP, "ip": T1, "source": "otx_passive_dns", "first": "2024-01-01", "last": "2026-01-01"}])

    def test_covers_host_by_cert_key(self):
        (query, params), = self.writer.statements("COVERS_HOST")
        self.assertIn("MATCH (c:Certificate {cert_key: v.cert_key, user_id: $uid, project_id: $pid})", query)
        self.assertNotIn("MERGE (c:Certificate", query)
        # *.example.com covers app.example.com; nothing covers shop.example.net.
        self.assertEqual(params["covers"], [{"cert_key": f"sha256:{FP}", "name": APP}])

    def test_every_statement_is_tenant_scoped(self):
        for query, params in self.writer.session.calls:
            for node in re.findall(r"\((\w+):(\w+) \{([^}]*)\}", query):
                self.assertIn("user_id", node[2], query)
                self.assertIn("project_id", node[2], query)

    def test_stats(self):
        self.assertEqual(self.stats["names_scanned"], 2)
        self.assertEqual(self.stats["names_recorded"], 1)
        self.assertEqual(self.stats["errors"], [])

    def test_a_scanned_name_is_never_also_recorded(self):
        (_, params), = self.writer.statements("MERGE (ed:ExternalDomain")
        self.assertEqual([r["name"] for r in params["rows"]], ["old.example.com"])


class TestScannedNamesEdges(unittest.TestCase):
    def test_the_pin_falls_back_to_the_dns_entry(self):
        recon = _scanned_recon()
        del recon["ip_hostnames"]["candidates"][APP]["resolves_to_now"]
        recon["dns"] = {"subdomains": {APP: {"ips": {"ipv4": [T2], "ipv6": []}}}}
        w = _ScannedWriter()
        w.update_graph_from_ip_hostnames(recon, UID, PID)
        (_, params), = w.statements("[r:RESOLVES_TO]")
        self.assertIn({"name": APP, "ip": T2, "record_type": "A"}, params["edges"])

    def test_a_scanned_name_with_no_org_is_skipped(self):
        recon = _scanned_recon()
        recon["metadata"]["ip_mode_hosts"] = {}
        recon["ip_hostnames"]["candidates"][APP]["org_domain"] = None
        w = _ScannedWriter()
        stats = w.update_graph_from_ip_hostnames(recon, UID, PID)
        (_, params), = w.statements("MERGE (s:Subdomain")
        self.assertEqual([r["name"] for r in params["rows"]], [SHOP])
        self.assertEqual(stats["names_scanned"], 1)

    def test_no_scanned_name_writes_no_scanned_statement(self):
        w = _ScannedWriter()
        w.update_graph_from_ip_hostnames(_recon({"x.example.com": _candidate([T1])}), UID, PID)
        self.assertEqual(w.statements("MERGE (s:Subdomain"), [])
        self.assertEqual(w.statements("MERGE (d:Domain"), [])

    def test_a_failed_scanned_batch_is_reported(self):
        w = _ScannedWriter(fail_on="MERGE (s:Subdomain")
        stats = w.update_graph_from_ip_hostnames(_scanned_recon(), UID, PID)
        self.assertEqual(stats["names_scanned"], 0)
        self.assertTrue(any(APP in e for e in stats["errors"]))

    def test_a_failed_org_seed_is_reported_and_the_names_still_written(self):
        w = _ScannedWriter()
        with unittest.mock.patch.object(DomainMixin, "ensure_root_domains", side_effect=RuntimeError("down")):
            stats = w.update_graph_from_ip_hostnames(_scanned_recon(), UID, PID)
        self.assertTrue(any("org Domain" in e for e in stats["errors"]))
        self.assertEqual(stats["names_scanned"], 2)

    def test_cert_coverage_is_tls_name_matching(self):
        self.assertTrue(ihm._covers(APP, [APP]))
        self.assertTrue(ihm._covers(APP, ["*.EXAMPLE.com."]))
        self.assertFalse(ihm._covers("b.app.example.com", ["*.example.com"]))
        self.assertFalse(ihm._covers("example.com", ["*.example.com"]))
        self.assertFalse(ihm._covers(APP, [None, ""]))

    def test_only_certificates_seen_on_target_ips_cover_a_name(self):
        recon = _scanned_recon()
        recon["tlsx"]["by_target"] = {
            "198.51.100.7:443": {"scanned_ip": "198.51.100.7", "fingerprint_sha256": "ef" * 32,
                                 "subject_cn": APP},
            f"{T2}:443": {"ip": T2, "subject_cn": SHOP}}
        w = _ScannedWriter()
        w.update_graph_from_ip_hostnames(recon, UID, PID)
        (_, params), = w.statements("COVERS_HOST")
        self.assertEqual([c["name"] for c in params["covers"]], [SHOP])

    def test_the_composed_client_has_the_allowed_domain_site(self):
        from graph_db.mixins.recon_mixin import ReconMixin
        self.assertTrue(hasattr(ReconMixin, "ensure_root_domains"))
        self.assertTrue(hasattr(ReconMixin, "update_graph_from_ip_hostnames"))

    def test_the_dated_sources_are_the_collectors(self):
        """Only these sources give the collector a date (otx first/last; Censys,
        FOFA, ZoomEye last): the history edge never claims a date a live
        source did not give."""
        self.assertEqual(ihm._DATED_SOURCES, frozenset({
            "otx_passive_dns", "censys_rdns", "censys_cert", "fofa_host", "fofa_domain", "fofa_cname",
            "fofa_cert", "zoomeye_hostname", "zoomeye_rdns"}))


if __name__ == "__main__":
    unittest.main()
