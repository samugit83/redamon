"""§6 phase 4: names urlscan found join the scan (F1), late names get their
IPs, ports and probe (F2), GAU keeps documents (F4).

DNS, the port scan and httpx are injected: nothing is resolved or sent.
Names are example.test; addresses are the lab subnet 192.88.97.0/24.
"""
from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import main as recon_main  # noqa: E402
from recon.helpers import late_names as ln  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402

NOW = datetime(2026, 11, 1, tzinfo=timezone.utc)
ROOT = "example.test"


def _dns(ip="192.88.97.10"):
    return {"records": {"A": [ip]}, "ips": {"ipv4": [ip], "ipv6": []}, "has_records": True}


class TestInjectableHosts:
    DATA = {"host_last_seen": {"new.example.test": "2026-10-20T00:00:00.000Z",
                               "old.example.test": "2025-01-01T00:00:00.000Z",
                               "gone.example.test": "2026-10-30T00:00:00.000Z",
                               "mid.example.test": "2026-09-01T00:00:00Z"},
            "takeover_pages": [{"host": "gone.example.test"}]}

    def test_recent_newest_first_takeover_pages_left_out(self):
        assert u.injectable_hosts(self.DATA, {}, now=NOW) == ["new.example.test", "mid.example.test"]

    def test_age_and_cap(self):
        assert u.injectable_hosts(self.DATA, {"URLSCAN_INJECT_MAX_AGE_DAYS": 30}, now=NOW) == ["new.example.test"]
        assert u.injectable_hosts(self.DATA, {"URLSCAN_MAX_INJECTED_HOSTS": 1}, now=NOW) == ["new.example.test"]
        assert u.injectable_hosts(self.DATA, {"URLSCAN_MAX_INJECTED_HOSTS": 0}, now=NOW) == []

    def test_the_enrichment_records_when_each_target_host_was_seen(self):
        from unittest.mock import patch
        visit = {"page": {"url": "https://a.example.test/x", "domain": "a.example.test", "status": "200"},
                 "task": {"url": "https://start.example.test/", "time": "2026-10-01T00:00:00.000Z",
                          "visibility": "public", "uuid": "u1"}}
        other = {"page": {"url": "https://x.other.test/", "domain": "x.other.test"},
                 "task": {"url": "https://x.other.test/", "time": "2026-10-02T00:00:00.000Z"}}
        with patch.object(u, "_urlscan_search", return_value=u.SearchResults([visit, other])):
            out = u.run_urlscan_enrichment({"domain": ROOT, "metadata": {}}, {"URLSCAN_ENABLED": True})
        assert out["urlscan"]["host_last_seen"] == {"a.example.test": "2026-10-01T00:00:00.000Z",
                                                    "start.example.test": "2026-10-01T00:00:00.000Z"}


def _merge(extra, target_info=None, answers=None, settings=None, dns_enabled=True, wildcard=None):
    answers = answers if answers is not None else {}

    def resolver(root, names, **_kw):
        return {"domain": {}, "subdomains": {n: answers[n] for n in names if n in answers}}
    info = {"mode": "enumerate", "include_root_domain": False, **(target_info or {})}
    return recon_main.merge_group_hosts(
        {"subdomains": ["www.example.test"], "dns": {"subdomains": {"www.example.test": _dns()}}},
        info, ROOT, settings or {}, dns_enabled, resolver=resolver,
        extra_hosts=[(h, "urlscan") for h in extra],
        wildcard_filter=wildcard or (lambda names: names))


class TestF1MergeGroupHosts:
    def test_an_in_scope_name_is_resolved_kept_and_keeps_its_source(self):
        merged = _merge(["new.example.test"], answers={"new.example.test": _dns("192.88.97.11")})
        assert "new.example.test" in merged["subdomains"]
        assert merged["dns"]["subdomains"]["new.example.test"]["source"] == "urlscan"
        assert merged["injected"] == ["new.example.test"]

    def test_the_port_scan_sees_it(self):
        from recon.helpers.target_helpers import extract_targets_from_recon
        merged = _merge(["new.example.test"], answers={"new.example.test": _dns("192.88.97.11")})
        ips, hostnames, _ = extract_targets_from_recon({"domain": ROOT, "dns": merged["dns"],
                                                       "metadata": {"include_root_domain": False}})
        assert "192.88.97.11" in ips and "new.example.test" in hostnames

    def test_an_exact_group_takes_none(self):
        merged = _merge(["new.example.test"], target_info={"mode": "exact"},
                        answers={"new.example.test": _dns()})
        assert "new.example.test" not in merged["subdomains"] and merged["injected"] == []

    def test_outside_the_root_the_roe_or_bad_syntax_takes_none(self):
        merged = _merge(["x.other.test", "bad_name!.example.test", "excluded.example.test", ROOT],
                        settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["excluded.example.test"]},
                        answers={h: _dns() for h in ("x.other.test", "excluded.example.test", ROOT)})
        assert merged["injected"] == []
        assert "excluded.example.test" not in merged["dns"]["subdomains"]

    def test_unresolved_private_and_wildcard_names_are_dropped(self):
        merged = _merge(["dead.example.test", "priv.example.test", "wild.example.test"],
                        answers={"priv.example.test": _dns("10.0.0.5"), "wild.example.test": _dns()},
                        wildcard=lambda names: [n for n in names if not n.startswith("wild.")])
        assert merged["injected"] == []
        for h in ("dead.example.test", "priv.example.test", "wild.example.test"):
            assert h not in merged["subdomains"] and h not in merged["dns"]["subdomains"]

    def test_with_dns_off_none_joins(self):
        assert _merge(["new.example.test"], dns_enabled=False)["injected"] == []

    def test_wiring_only_where_discovery_runs(self):
        src = (PROJECT_ROOT / "recon" / "main.py").read_text()
        call = src.index("injectable_hosts(g1_results[\"urlscan\"], _settings)")
        assert "if discovery_enabled and g1_results.get(\"urlscan\"):" in src[call - 300:call]
        assert "extra_hosts=_urlscan_names" in src
        # The filtered-mode branch never calls it.
        filtered = src[src.index("if filtered_mode:", src.index("def run_domain_recon")):
                       src.index("# FULL DISCOVERY MODE")]
        assert "injectable_hosts" not in filtered


class TestF2LateNames:
    def test_give_dns_stores_addresses_keeps_source_and_drops_private(self):
        combined = {"dns": {"subdomains": {"san.example.test": {"has_records": True, "source": "certificate_san"},
                                           "priv.example.test": {"has_records": True}}}}
        answers = {"san.example.test": _dns("192.88.97.12"), "priv.example.test": _dns("127.0.0.1")}
        got = ln.give_dns(combined, ["san.example.test", "priv.example.test"], {}, lookup=answers.get)
        assert got == ["san.example.test"]
        entry = combined["dns"]["subdomains"]["san.example.test"]
        assert entry["ips"]["ipv4"] == ["192.88.97.12"] and entry["source"] == "certificate_san"
        assert "priv.example.test" not in combined["dns"]["subdomains"]

    def test_a_scanned_address_lends_its_ports_without_a_packet(self):
        combined = {"dns": {"subdomains": {"san.example.test": _dns("192.88.97.10"),
                                           "fresh.example.test": _dns("192.88.97.99")}},
                    "port_scan": {"by_ip": {"192.88.97.10": {"ip": "192.88.97.10", "hostnames": ["www.example.test"],
                                                             "ports": [443, 8080]}},
                                  "by_host": {"www.example.test": {"host": "www.example.test", "ip": "192.88.97.10",
                                                                   "ports": [443, 8080], "port_details": [
                                                                       {"port": 443, "protocol": "tcp", "service": "https",
                                                                        "product": "nginx"}]}}}}
        unscanned = ln.attach_known_ports(combined, ["san.example.test", "fresh.example.test"])
        assert unscanned == ["fresh.example.test"]
        row = combined["port_scan"]["by_host"]["san.example.test"]
        assert row["ports"] == [443, 8080] and row["port_details"][0]["product"] == "nginx"
        assert "san.example.test" in combined["port_scan"]["by_ip"]["192.88.97.10"]["hostnames"]

    def test_a_san_name_after_httpx_gets_ips_ports_and_a_base_url(self):
        combined = {"domain": ROOT, "metadata": {"scope_mode": "enumerate", "root_domain": ROOT},
                    "dns": {"subdomains": {"san.example.test": {"has_records": True, "source": "certificate_san"}}},
                    "port_scan": {"by_ip": {}, "by_host": {}, "all_ports": [80]},
                    "http_probe": {"by_url": {"https://www.example.test": {"status_code": 200}}}}
        calls = []

        def port_scanner(sub, output_file=None, settings=None):
            calls.append(("ports", sorted(sub["dns"]["subdomains"])))
            sub["port_scan"] = {"by_ip": {"192.88.97.12": {"ip": "192.88.97.12", "hostnames": ["san.example.test"],
                                                            "ports": [443]}},
                                "by_host": {"san.example.test": {"host": "san.example.test", "ip": "192.88.97.12",
                                                                 "ports": [443], "port_details": []}},
                                "all_ports": [443]}

        def http_prober(sub, output_file=None, settings=None):
            calls.append(("httpx", sorted(sub["port_scan"]["by_host"])))
            sub["http_probe"] = {"by_url": {"https://san.example.test": {"status_code": 200, "host": "san.example.test"}},
                                 "by_host": {"san.example.test": {"live_urls": ["https://san.example.test"]}}}

        with pytest.MonkeyPatch().context() as mp:
            mp.setattr(ln, "give_dns", lambda c, names, s, lookup=None: (
                c["dns"]["subdomains"]["san.example.test"].update(_dns("192.88.97.12")) or ["san.example.test"]))
            sub = ln.scan_late_names(combined, ["san.example.test"], {}, probe_http=True, label="SAN",
                                     port_scanner=port_scanner, http_prober=http_prober)
        assert calls == [("ports", ["san.example.test"]), ("httpx", ["san.example.test"])]
        assert combined["dns"]["subdomains"]["san.example.test"]["ips"]["ipv4"] == ["192.88.97.12"]
        assert set(combined["http_probe"]["by_url"]) == {"https://www.example.test", "https://san.example.test"}
        assert combined["port_scan"]["all_ports"] == [80, 443]
        assert set(sub["http_probe"]["by_url"]) == {"https://san.example.test"}

    def test_before_the_port_scan_only_dns_and_never_a_raise(self):
        assert ln.scan_late_names({}, ["x.example.test"], {"DNS_ENABLED": False},
                                  probe_http=True, label="t") is None
        assert ln.scan_late_names(None, ["x"], {}, probe_http=True, label="t") is None

    def test_wiring(self):
        src = (PROJECT_ROOT / "recon" / "main.py").read_text()
        domain = src[src.index("def run_domain_recon"):]
        assert domain.count("_late_names(combined_result, _before") == 4
        assert 'after_port_scan=False, probe_http=False, label="Uncover"' in domain
        assert 'after_port_scan=True, probe_http=False, label="tlsx"' in domain
        assert 'after_port_scan=True, probe_http=True, label="certificate SAN"' in domain
        assert 'after_port_scan=True, probe_http=True, label="JS Recon"' in domain


class TestF4GauKeepsDocuments:
    def test_the_default_skips_media_only(self):
        from recon.project_settings import DEFAULT_SETTINGS
        from recon.helpers.resource_enum.gau_helpers import filter_gau_url
        blacklist = DEFAULT_SETTINGS["GAU_BLACKLIST_EXTENSIONS"]
        for ext in ("pdf", "docx", "xlsx", "zip", "gz", "tar"):
            assert ext not in blacklist
        assert filter_gau_url("https://files.example.test/invoices/2026-10.pdf", blacklist)
        assert not filter_gau_url("https://files.example.test/logo.png", blacklist)

    def test_prisma_default_matches(self):
        prisma = (PROJECT_ROOT / "webapp" / "prisma" / "schema.prisma").read_text()
        line = next(l for l in prisma.splitlines() if l.strip().startswith("gauBlacklistExtensions"))
        assert '"pdf"' not in line and '"zip"' not in line and '"png"' in line
