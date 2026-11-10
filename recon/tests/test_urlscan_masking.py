"""S4 / S5 / B10 / B11 in the urlscan module: what the recon JSON keeps.

Addresses are in 192.88.97.0/24, the urlscan lab's test subnet: Python counts
the documentation ranges (192.0.2.0/24...) as private, which the scope rule
rightly refuses.

S4: every urlscan URL is masked wherever it is requested or keyed, parameter
types are computed from the values, and the full URL is kept only in the
display fields (graph_db/display_only.py). S5/B11: a visit's address is kept only for a host the scan may target
(group scope, RoE) and when it is routable.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.display_only import strip_display_only  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402

T1 = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"


def _visit(url, ip="192.88.97.10", domain=None, **page):
    host = domain or url.split("/")[2]
    p = {"url": url, "domain": host, "ip": ip, "status": "200"}
    p.update(page)
    return {"page": p, "task": {"url": url, "time": "2026-10-01T00:00:00.000Z",
                                "visibility": "public", "uuid": "uuid-" + host},
            "screenshot": f"https://urlscan.io/screenshots/uuid-{host}.png"}


def _run(results, **settings):
    base = {"URLSCAN_ENABLED": True}
    base.update(settings)
    with patch.object(u, "_urlscan_search", return_value=u.SearchResults(results)):
        out = u.run_urlscan_enrichment({"domain": "example.test", "metadata": {}}, base)
    return out["urlscan"]


class TestMasking:
    def test_b10_raw_values_only_in_display_fields(self):
        data = _run([
            _visit("https://app.example.test/api/items?id=5&session=abc123"),
            _visit(f"https://other.test/share/{T1}?k=v", domain="other.test"),
            _visit(f"https://auth.example.test/reset?token={T1}"),
        ])
        blob = json.dumps(strip_display_only(data))
        assert T1 not in blob and "abc123" not in blob and "id=5" not in blob
        row, = data["urls_with_paths"]
        assert row["full_url"] == "https://app.example.test/api/items?id=***&session=***"
        assert row["unmasked_url"] == "https://app.example.test/api/items?id=5&session=abc123"
        assert row["params"] == {"id": "***", "session": "***"}
        ext, = data["external_domains"]
        assert ext["url"] == "https://other.test"
        by_host = {e["domain"]: e for e in data["entries"]}
        assert by_host["auth.example.test"]["unmasked_url"] == f"https://auth.example.test/reset?token={T1}"
        # A third party's page keeps its origin only, even for display.
        assert by_host["other.test"]["unmasked_url"] == ""

    def test_parameter_types_are_computed_before_masking(self):
        data = _run([_visit("https://app.example.test/go?id=5&next=https://a.example.test/x")])
        types = data["urls_with_paths"][0]["param_types"]
        assert types["id"] == "integer"
        assert types["next"] in ("url", "path")

    def test_a_quarantined_visit_keeps_its_screenshot_and_scan_id(self):
        data = _run([_visit(f"https://auth.example.test/reset?token={T1}"),
                     _visit("https://app.example.test/about")])
        by_host = {e["domain"]: e for e in data["entries"]}
        assert by_host["auth.example.test"]["screenshot_url"].endswith("uuid-auth.example.test.png")
        assert by_host["auth.example.test"]["scan_id"] == "uuid-auth.example.test"
        assert by_host["auth.example.test"]["quarantined"] is True
        assert by_host["app.example.test"]["scan_id"] == "uuid-app.example.test"


class TestHostAndIpScope:
    def test_s5_only_target_hosts_with_routable_ips(self):
        data = _run([
            _visit("https://app.example.test/", ip="192.88.97.10"),
            _visit("https://lan.example.test/", ip="10.1.2.3"),
            _visit("https://excluded.example.test/", ip="192.88.97.20"),
            _visit("https://other.test/", ip="192.88.97.99", domain="other.test"),
        ], ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["excluded.example.test"])
        flags = {e["domain"]: (e["in_scope"], e["ip_in_scope"]) for e in data["entries"]}
        assert flags["app.example.test"] == (True, True)
        assert flags["lan.example.test"] == (True, False)
        assert flags["excluded.example.test"] == (False, False)
        assert flags["other.test"] == (False, False)
        assert data["ips_discovered"] == ["192.88.97.10"]

    def test_b11_an_exact_group_keeps_only_its_listed_hosts(self):
        groups = [{"scanRoot": "example.test", "orgDomain": "example.test", "mode": "exact",
                   "includeRoot": False, "exactHosts": ["www.example.test"]}]
        data = _run([_visit("https://www.example.test/"), _visit("https://dev.example.test/")],
                    SCOPE_GROUPS=groups)
        flags = {e["domain"]: e["in_scope"] for e in data["entries"]}
        assert flags == {"www.example.test": True, "dev.example.test": False}

    def test_an_ip_in_an_excluded_range_is_not_kept(self):
        data = _run([_visit("https://app.example.test/", ip="203.0.113.7")],
                    ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["203.0.113.0/24"])
        assert data["entries"][0]["ip_in_scope"] is False
        assert data["ips_discovered"] == []
