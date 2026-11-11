"""An IP literal is in httpx's scope only as one of the run's own addresses (L-6).

`is_host_in_scope` returned True for any IP outside filtered mode, so when
`www.example.com` redirected to `http://203.0.113.50/sso`, that page's title,
technologies and certificate were credited to the target (a residual of plan
03.1, see test_http_probe_redirect_scope.py). An IP is now in scope only when
the run resolved, port-scanned or probed it, and the RoE does not exclude it;
an IP-mode or EXACT run keeps its explicit host list.
Reserved names and documentation addresses only; no Docker, no network.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.main_recon_modules import http_probe as hp  # noqa: E402

WWW, OWN_IP = "www.example.com", "192.0.2.10"
FOREIGN_IP = "203.0.113.50"
EXCLUDED_IP = "198.51.100.20"


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _line(url, final_url=None, title="Example page", tech=("Nginx",), **extra):
    entry = {
        "url": url, "input": extra.pop("input", url), "status_code": 200, "title": title,
        "webserver": "nginx", "tech": list(tech), "content_type": "text/html",
        "tls": {"subject_cn": "sso.example.net", "issuer_cn": "Example CA"},
        "a": [OWN_IP],
    }
    if final_url:
        entry["final_url"] = final_url
        entry["chain_status_codes"] = [302, 200]
    entry.update(extra)
    return entry


def _parse(tmp_path, *entries, **kw):
    out = tmp_path / "httpx.jsonl"
    out.write_text("".join(json.dumps(e) + "\n" for e in entries))
    return hp.parse_httpx_output(str(out), root_domain=kw.pop("root", "example.com"), **kw)


# --------------------------------------------------------------------------
# is_host_in_scope
# --------------------------------------------------------------------------

def test_an_ip_is_in_scope_only_as_a_run_address():
    assert not hp.is_host_in_scope(FOREIGN_IP, "example.com")
    assert not hp.is_host_in_scope(FOREIGN_IP, "example.com", run_addresses=frozenset({OWN_IP}))
    assert hp.is_host_in_scope(OWN_IP, "example.com", run_addresses=frozenset({OWN_IP}))
    assert hp.is_host_in_scope("2001:db8::10", "example.com",
                               run_addresses=frozenset({"2001:db8::10"}))


def test_a_name_is_judged_as_before():
    assert hp.is_host_in_scope(WWW, "example.com")
    assert not hp.is_host_in_scope("www.example.net", "example.com", run_addresses=frozenset({OWN_IP}))


def test_a_filtered_run_keeps_its_explicit_host_list():
    """IP mode stamps its IPs into subdomain_filter: the list decides, as before."""
    assert hp.is_host_in_scope(FOREIGN_IP, "ip-targets.p1", [FOREIGN_IP])
    assert not hp.is_host_in_scope(OWN_IP, "ip-targets.p1", [FOREIGN_IP],
                                   run_addresses=frozenset({OWN_IP}))


# --------------------------------------------------------------------------
# parse_httpx_output
# --------------------------------------------------------------------------

class TestARedirectToAnIpLiteral:
    def test_a_foreign_ip_page_is_not_credited_to_the_target(self, tmp_path):
        res = _parse(tmp_path, _line(f"http://{WWW}", f"http://{FOREIGN_IP}/sso", title="Foreign SSO",
                                     tech=("Keycloak",)),
                     run_addresses={OWN_IP})
        entry = res["by_url"][f"http://{WWW}"]
        assert entry["title"] is None and entry["technologies"] == []
        assert "tls" not in entry
        assert "Keycloak" not in res["technologies_found"]
        assert [d["domain"] for d in res["external_domains"]] == [FOREIGN_IP]

    def test_a_redirect_to_the_targets_own_address_keeps_its_page(self, tmp_path):
        res = _parse(tmp_path, _line(f"http://{WWW}", f"http://{OWN_IP}/home", title="Own home"),
                     run_addresses={OWN_IP})
        assert res["by_url"][f"http://{WWW}"]["title"] == "Own home"
        assert res["external_domains"] == []

    def test_an_ipv6_run_address_matches_in_any_spelling(self, tmp_path):
        res = _parse(tmp_path, _line(f"http://{WWW}", "http://[2001:DB8:0::10]/home", title="Own home"),
                     run_addresses={"2001:db8::10"})
        assert res["by_url"][f"http://{WWW}"]["title"] == "Own home"


class TestAProbedIpLiteral:
    def test_the_runs_own_address_is_kept(self, tmp_path):
        res = _parse(tmp_path, _line(f"http://{OWN_IP}", title="Own"), run_addresses={OWN_IP})
        assert res["by_url"][f"http://{OWN_IP}"]["title"] == "Own"

    def test_a_foreign_address_is_dropped(self, tmp_path):
        res = _parse(tmp_path, _line(f"http://{FOREIGN_IP}", title="Foreign"), run_addresses={OWN_IP})
        assert f"http://{FOREIGN_IP}" not in res["by_url"]
        assert res["summary"]["filtered_out_of_scope"] == 1


# --------------------------------------------------------------------------
# the run's addresses
# --------------------------------------------------------------------------

def _recon():
    return {
        "domain": "example.com",
        "metadata": {"root_domain": "example.com"},
        "dns": {"domain": {"ips": {"ipv4": ["192.0.2.1"], "ipv6": []}},
                "subdomains": {WWW: {"has_records": True, "ips": {"ipv4": [OWN_IP], "ipv6": ["2001:DB8::10"]}},
                               "legacy.example.com": {"has_records": True,
                                                      "ips": {"ipv4": [EXCLUDED_IP], "ipv6": []}}}},
        "port_scan": {"by_host": {"192.0.2.30": {"ip": "192.0.2.30", "port_details": []}},
                      "by_ip": {"192.0.2.31": {"ip": "192.0.2.31", "hostnames": [], "ports": [22]}}},
    }


def test_the_run_addresses_are_resolved_scanned_and_probed_ones():
    got = hp._run_addresses(_recon(), ["http://192.0.2.40:8080", f"https://{WWW}"], {})
    assert got == {"192.0.2.1", OWN_IP, "2001:db8::10", EXCLUDED_IP,
                   "192.0.2.30", "192.0.2.31", "192.0.2.40"}


def test_the_run_addresses_leave_out_what_the_roe_excludes():
    settings = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["198.51.100.0/24"]}
    got = hp._run_addresses(_recon(), [], settings)
    assert EXCLUDED_IP not in got and OWN_IP in got
    # Reading the rules sends nothing, so it records no refusal.
    assert not [g for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


# --------------------------------------------------------------------------
# run_http_probe, end to end (docker and httpx faked)
# --------------------------------------------------------------------------

def test_run_http_probe_credits_no_foreign_ip_page(tmp_path):
    recon = {
        "domain": "example.com",
        "metadata": {"root_domain": "example.com"},
        "port_scan": {"by_host": {
            WWW: {"host": WWW, "ip": OWN_IP, "ports": [80],
                  "port_details": [{"port": 80, "protocol": "tcp", "service": "http"}]},
            OWN_IP: {"host": OWN_IP, "ip": OWN_IP, "ports": [80],
                     "port_details": [{"port": 80, "protocol": "tcp", "service": "http"}]},
        }, "by_ip": {OWN_IP: {"ip": OWN_IP, "hostnames": [WWW], "ports": [80]}}},
    }
    written = {}

    def _build(targets_file, output_file, settings, probe_hosts=None, container_name=None):
        written["output"] = output_file
        return ["httpx"]

    def _popen(cmd, **_kw):
        Path(written["output"]).write_text(
            json.dumps(_line(f"http://{WWW}", f"http://{FOREIGN_IP}/sso", title="Foreign SSO",
                             tech=("Keycloak",))) + "\n"
            + json.dumps(_line(f"http://{OWN_IP}", title="Own")) + "\n")
        proc = mock.MagicMock()
        proc.communicate.return_value = ("", "")
        proc.returncode = 0
        return proc

    with mock.patch.object(hp, "is_docker_installed", return_value=True), \
            mock.patch.object(hp, "is_docker_running", return_value=True), \
            mock.patch.object(hp, "pull_httpx_docker_image", return_value=True), \
            mock.patch.object(hp, "build_httpx_command", side_effect=_build), \
            mock.patch.object(hp.subprocess, "Popen", side_effect=_popen):
        out = hp.run_http_probe(recon, None, {"BANNER_GRAB_ENABLED": False})

    by_url = out["http_probe"]["by_url"]
    assert by_url[f"http://{OWN_IP}"]["title"] == "Own"
    assert by_url[f"http://{WWW}"]["title"] is None
    assert "Keycloak" not in out["http_probe"]["technologies_found"]
