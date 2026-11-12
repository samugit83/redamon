"""IP-mode Subdomain nodes take their HTTP status from the per-host loop (L-18).

httpx probes an IP-mode target by its address, so http_probe.by_host is keyed
by the IP literal, while the target's Subdomain node carries the label minted
for it (`203.0.113.10` -> `203-0-113-10`, metadata.ip_to_hostname). The
per-host loop of update_graph_from_http_probe matched `Subdomain {name: <key>}`
with the literal, found nothing, and no IP-mode Subdomain ever got a status;
only the `no_http` sweep translated. A name the selection rule scanned
(metadata.ip_mode_hosts, its late probe keyed by the name itself) keeps
matching by its own name, and domain mode is unchanged.

The Neo4j session is a fake that records each statement: the real writer runs,
only the database is replaced. tests/test_http_probe_ip_mode_subdomain_status_live.py
proves the same end to end on a real graph. Documentation ranges and reserved
names only.

Run: ./redamon.sh test unit (root-agent section), or one file in the agent image.
"""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.http_mixin import HttpMixin  # noqa: E402

T1, T2 = "203.0.113.10", "2001:db8::10"
L1, L2 = "203-0-113-10", "2001-db8--10"
APP = "app.example.com"
UID, PID = "u1", "cmhttpstatusipmode00000001"
MOCK = f"ip-targets.{PID}"


class _Result:
    def single(self):
        return {"linked": 0, "count": 0, "c": 0}

    def __iter__(self):
        return iter([])


class _Session:
    def __init__(self, queries):
        self.queries = queries

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **kwargs):
        self.queries.append((query, kwargs))
        return _Result()


class _Driver:
    def __init__(self, queries):
        self.queries = queries

    def session(self):
        return _Session(self.queries)


class _Client(HttpMixin):
    def __init__(self):
        self.queries = []
        self.driver = _Driver(self.queries)


def _host(name, codes):
    url = f"https://{name}/" if ":" not in name else f"https://[{name}]/"
    return {"hostname": name, "urls": [url], "live_urls": [url] if codes else [],
            "technologies": [], "servers": [], "status_codes": codes}


def _ip_run(by_host, **metadata):
    return {
        "domain": MOCK,
        "metadata": {"ip_mode": True, "root_domain": MOCK, "expanded_ips": [T1, T2],
                     "ip_to_hostname": {T1: L1, T2: L2}, **metadata},
        "subdomains": [L1, L2],
        "http_probe": {"scan_metadata": {}, "by_url": {}, "by_host": by_host},
    }


def _statuses(client):
    """{Subdomain name: status} from the per-host status statements."""
    out = {}
    for query, kw in client.queries:
        if "SET s.status = $status" in query:
            out[kw["hostname"]] = kw["status"]
    return out


class TestIpModeSubdomainStatus(unittest.TestCase):
    def test_the_ip_keyed_host_sets_the_status_on_its_label(self):
        client = _Client()
        client.update_graph_from_http_probe(_ip_run({T1: _host(T1, [200, 404])}), UID, PID)
        self.assertEqual(_statuses(client), {L1: "200"})

    def test_an_ipv6_target_takes_its_label_too(self):
        client = _Client()
        client.update_graph_from_http_probe(_ip_run({T2: _host(T2, [503])}), UID, PID)
        self.assertEqual(_statuses(client), {L2: "503"})

    def test_no_subdomain_is_ever_matched_by_an_ip_literal(self):
        client = _Client()
        client.update_graph_from_http_probe(
            _ip_run({T1: _host(T1, [200]), T2: _host(T2, [301])}), UID, PID)
        self.assertEqual(_statuses(client), {L1: "200", L2: "301"})

    def test_the_status_codes_and_live_count_ride_with_the_label(self):
        client = _Client()
        client.update_graph_from_http_probe(_ip_run({T1: _host(T1, [200, 404])}), UID, PID)
        kw = next(kw for q, kw in client.queries if "SET s.status = $status" in q)
        self.assertEqual((kw["status_codes"], kw["live_count"]), ([200, 404], 1))

    def test_a_probed_label_is_still_not_demoted_to_no_http(self):
        client = _Client()
        client.update_graph_from_http_probe(_ip_run({T1: _host(T1, [200])}), UID, PID)
        demoted = next((set(kw["hosts"]) for q, kw in client.queries if "'no_http'" in q), set())
        self.assertEqual(demoted, {L2})


class TestScannedNameKeepsItsOwnName(unittest.TestCase):
    """P4: a name the selection rule scanned is a Subdomain of its own name,
    and its late probe (a subset of the run, with the run's metadata) is keyed
    by that name."""

    def _late(self):
        run = _ip_run({APP: _host(APP, [404])}, ip_mode_hosts={APP: "example.com"})
        run["subdomains"] = [APP]
        return run

    def test_the_late_subset_writes_the_name_itself(self):
        client = _Client()
        client.update_graph_from_http_probe(self._late(), UID, PID)
        self.assertEqual(_statuses(client), {APP: "404"})

    def test_the_merged_run_writes_the_name_and_the_label(self):
        run = _ip_run({T1: _host(T1, [200]), APP: _host(APP, [404])},
                      ip_mode_hosts={APP: "example.com"})
        run["subdomains"].append(APP)
        client = _Client()
        client.update_graph_from_http_probe(run, UID, PID)
        self.assertEqual(_statuses(client), {L1: "200", APP: "404"})


class TestDomainModeUnchanged(unittest.TestCase):
    def test_a_hostname_key_matches_itself(self):
        client = _Client()
        client.update_graph_from_http_probe({
            "domain": "example.com", "metadata": {"root_domain": "example.com"},
            "subdomains": ["www.example.com"],
            "http_probe": {"scan_metadata": {}, "by_url": {},
                           "by_host": {"www.example.com": _host("www.example.com", [200])}},
        }, UID, PID)
        self.assertEqual(_statuses(client), {"www.example.com": "200"})

    def test_an_ip_key_without_a_label_map_is_matched_as_written(self):
        client = _Client()
        client.update_graph_from_http_probe({
            "domain": "example.com", "metadata": {"root_domain": "example.com"},
            "subdomains": [],
            "http_probe": {"scan_metadata": {}, "by_url": {}, "by_host": {T1: _host(T1, [200])}},
        }, UID, PID)
        self.assertEqual(_statuses(client), {T1: "200"})


class TestTenantScope(unittest.TestCase):
    def test_every_subdomain_statement_carries_the_tenant(self):
        client = _Client()
        client.update_graph_from_http_probe(
            _ip_run({T1: _host(T1, [200]), APP: _host(APP, [404])}), UID, PID)
        sub_writes = [(q, kw) for q, kw in client.queries if "Subdomain" in q]
        self.assertTrue(sub_writes)
        for query, kw in sub_writes:
            self.assertIn("user_id: $user_id", query)
            self.assertIn("project_id: $project_id", query)
            self.assertEqual((kw["user_id"], kw["project_id"]), (UID, PID))


if __name__ == "__main__":
    unittest.main()
