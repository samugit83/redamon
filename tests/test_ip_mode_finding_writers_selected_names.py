"""IP mode: the resource and JS-recon writers keep a selected hostname's findings
and drop a recorded one's (P4, roadmap "Tests first"; the vuln writer is in
tests/test_graph_scope_ip_mode_hosts.py).

An IP-mode run's targets are its addresses plus the hostnames its selection
rule scanned: those join the run's scope list (metadata.subdomain_filter)
before the late scan, so every finding writer's shared gate (build_host_scope,
and js_endpoint_scope on top of it) admits them. A name the run only recorded
is in no scope list (invariant I-4): a crawler or a JS file that reached it
leaves no Endpoint behind.

Fake sessions record each statement. Documentation ranges and reserved names only.
"""
import os
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402
from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402

T1 = "203.0.113.10"
SELECTED, RECORDED = "app.example.com", "old.example.com"
MOCK = "ip-targets.cmfindingwriters000000001"


class _Record(dict):
    """Every RETURN a writer reads: created/linked/enriched counts."""

    def __missing__(self, key):
        return 1


class _Result:
    def single(self):
        return _Record()


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        return _Result()

    def execute_write(self, work):
        return work(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Driver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _Session(self.calls)


def _ip_run(**parts):
    run = {
        "domain": MOCK,
        "subdomains": ["203-0-113-10", SELECTED],
        "metadata": {"ip_mode": True, "root_domain": MOCK, "expanded_ips": [T1], "filtered_mode": True,
                     "subdomain_filter": [T1, "203-0-113-10", SELECTED],
                     "ip_mode_hosts": {SELECTED: "example.com"}},
        "dns": {"domain": {}, "subdomains": {
            SELECTED: {"has_records": True, "ips": {"ipv4": [T1], "ipv6": []}, "source": "ip_hostname_selection"}}},
    }
    run.update(parts)
    return run


def _endpoint_bases(calls):
    return sorted({p["baseurl"] for q, p in calls if q.startswith("MERGE (e:Endpoint") and "baseurl" in p})


class TestResourceWriter(unittest.TestCase):
    def test_a_selected_names_endpoints_are_kept_and_a_recorded_ones_dropped(self):
        writer = ResourceMixin()
        writer.driver = _Driver()
        endpoint = {"/login": {"methods": ["GET"], "sources": ["katana"], "parameters": {}}}
        stats = writer.update_graph_from_resource_enum(_ip_run(resource_enum={
            "by_base_url": {f"https://{SELECTED}": {"endpoints": endpoint},
                            f"https://{RECORDED}": {"endpoints": endpoint},
                            f"http://{T1}": {"endpoints": endpoint}},
            "forms": []}), "u1", "p1")
        self.assertEqual(_endpoint_bases(writer.driver.calls), [f"http://{T1}", f"https://{SELECTED}"])
        self.assertNotIn(RECORDED, " ".join(q + repr(p) for q, p in writer.driver.calls))
        self.assertEqual(stats["errors"], [])


class TestJsReconWriter(unittest.TestCase):
    def test_a_selected_names_endpoints_are_kept_and_a_recorded_ones_dropped(self):
        writer = JsReconMixin()
        writer.driver = _Driver()

        def endpoint(base):
            return {"path": "/api/v1/users", "method": "GET", "source_js": f"{base}/app.js", "base_url": base,
                    "validation_status": "hittable"}

        stats = writer.update_graph_from_js_recon(_ip_run(js_recon={
            "scan_metadata": {"scan_timestamp": "2026-11-11T00:00:00Z"},
            "endpoints": [endpoint(f"https://{SELECTED}"), endpoint(f"https://{RECORDED}"),
                          endpoint(f"http://{T1}")]}), "u1", "p1")
        self.assertEqual(_endpoint_bases(writer.driver.calls), [f"http://{T1}", f"https://{SELECTED}"])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)

    def test_without_the_selection_the_name_is_out_of_scope_too(self):
        """The same run before P4's insert: the name is in no scope list."""
        run = _ip_run(js_recon={"scan_metadata": {}, "endpoints": [
            {"path": "/a", "method": "GET", "source_js": f"https://{SELECTED}/app.js",
             "base_url": f"https://{SELECTED}", "validation_status": "hittable"}]})
        run["subdomains"].remove(SELECTED)
        run["metadata"]["subdomain_filter"].remove(SELECTED)
        writer = JsReconMixin()
        writer.driver = _Driver()
        stats = writer.update_graph_from_js_recon(run, "u1", "p1")
        self.assertEqual(_endpoint_bases(writer.driver.calls), [])
        self.assertEqual(stats["endpoints_out_of_scope"], 1)


if __name__ == "__main__":
    unittest.main()
