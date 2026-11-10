"""httpx and Wappalyzer add themselves to `Technology.detected_by` (R-25).

`detected_by` on a Technology node is the comma-joined list of every scanner that
saw it, and clear_recon_data spares a Technology only while that list holds
`gvm`. update_graph_from_http_probe applied it through `SET t += $props`, so an
httpx sighting of a GVM-tagged `nginx/1.19.0` reset `httpx,gvm` to `httpx` and the
next full recon deleted the node with its GVM vulnerabilities.

Hermetic: a fake driver records every query; the union itself runs in
test_http_probe_technology_provenance_live.py against a real Neo4j.
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

URL = "https://www.example.com"


class _Result:
    def single(self):
        return None

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
        self.queries.append((" ".join(query.split()), kwargs))
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


def _recon():
    return {
        "domain": "example.com", "subdomains": [], "metadata": {},
        "http_probe": {
            "scan_metadata": {},
            "by_host": {},
            "by_url": {URL: {"url": URL, "host": "www.example.com", "status_code": 200,
                             "ip": "192.0.2.10",
                             "technologies": ["Nginx:1.19.0", "Ubuntu"]}},
            "wappalyzer": {"by_url": {URL: [{"name": "jQuery", "version": "3.5.1"},
                                            {"name": "Bootstrap", "version": None}]}},
        },
    }


class TestTechnologyProvenanceIsUnioned(unittest.TestCase):
    def setUp(self):
        client = _Client()
        client.update_graph_from_http_probe(_recon(), "u1", "p1")
        self.writes = {kw["name"]: (q, kw) for q, kw in client.queries
                       if q.startswith("MERGE (t:Technology")}
        self.edges = [(q, kw) for q, kw in client.queries
                      if "MERGE (e)-[:USES_TECHNOLOGY" in q]

    def test_all_four_node_writes_ran(self):
        # with/without a version, from httpx and from Wappalyzer
        self.assertEqual(sorted(self.writes), ["Bootstrap", "Nginx", "Ubuntu", "jQuery"])
        self.assertEqual(self.writes["Nginx"][1]["version"], "1.19.0")
        self.assertEqual(self.writes["jQuery"][1]["version"], "3.5.1")
        self.assertIn("version: ''", self.writes["Ubuntu"][0])
        self.assertIn("version: ''", self.writes["Bootstrap"][0])

    def test_detected_by_never_rides_in_the_props_map(self):
        # `SET t += $props` overwrites; a GVM tag on the node would be lost.
        for name, (_q, kw) in self.writes.items():
            self.assertNotIn("detected_by", kw.get("props", {}), name)

    def test_each_write_adds_its_own_detector(self):
        detectors = {name: kw.get("detector") for name, (_q, kw) in self.writes.items()}
        self.assertEqual(detectors, {"Nginx": "httpx", "Ubuntu": "httpx",
                                     "jQuery": "wappalyzer", "Bootstrap": "wappalyzer"})

    def test_the_detector_is_merged_into_the_existing_list(self):
        for name, (q, _kw) in self.writes.items():
            self.assertIn("split(coalesce(t.detected_by, '') + ',' + $detector, ',')", q, name)
            self.assertIn("CASE WHEN s IN acc THEN acc ELSE acc + s END", q, name)
            # gvm last: clear_gvm_data strips only an exact 'gvm' or a ',gvm' suffix
            self.assertIn("[d IN seen WHERE d <> 'gvm'] + [d IN seen WHERE d = 'gvm']", q, name)

    def test_the_union_also_runs_when_the_node_already_exists(self):
        # A union inside ON CREATE only would leave a GVM-only versionless node
        # 'gvm', and a GVM rescan (clear_gvm_data) would delete what httpx saw.
        for name, (q, _kw) in self.writes.items():
            tail = q.split("WITH t,", 1)
            self.assertEqual(len(tail), 2, name)
            self.assertNotIn("ON CREATE", tail[1], name)
            self.assertNotIn("ON MATCH", tail[1], name)
            self.assertIn("SET t.detected_by =", tail[1], name)

    def test_the_tool_still_owns_its_other_fields(self):
        _q, kw = self.writes["Nginx"]
        self.assertEqual(kw["props"]["confidence"], 100)
        self.assertEqual(kw["props"]["version"], "1.19.0")

    def test_the_edge_keeps_the_single_detector(self):
        by_detector = sorted(q.split("detected_by: '", 1)[1].split("'", 1)[0]
                             for q, _kw in self.edges)
        self.assertEqual(by_detector, ["httpx", "httpx", "wappalyzer", "wappalyzer"])


if __name__ == "__main__":
    unittest.main()
