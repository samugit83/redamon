"""Domain mode: the redirect-chain check follows a hop only onto the run's own hosts.

check_direct_ip_http/https call _analyze_redirect_chain, which in domain mode
let requests follow every redirect the address answered with: a Location the
target writes sent the scanner to a third party, to an address the Rules of
Engagement exclude, or to an internal service (cloud metadata), and all the
hops shared one slot of the RoE pacer. IP mode already walked hop by hop
(_follow_admitted_redirects, 65365856).

In a domain run every hop now passes hop_guard.hop_refusal with the run's RoE
(module security_checks) and the run's admission rule: a name or address the
run itself resolved and the RoE admits. A refused hop is not sent and counts
no failure; the chain ends there, reported as where the target pointed. The
SSRF guard is not applied: an internal-network project's own private
addresses are its targets, and an address the run never resolved is refused
by the admission rule already. Each hop that is sent takes its own pacer slot.

Documentation ranges and reserved names only.
"""
import socket
import sys
import time as _time
from pathlib import Path
from unittest import mock
from urllib.parse import urljoin, urlsplit

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import request_pacer  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

APEX = "example.com"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
APP, APP_IP = "app.example.com", "192.0.2.8"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"
EXCLUDED_RANGE = "198.51.100.0/24"
THIRD = "sso.third-party.example.net"
METADATA = "169.254.169.254"
ONLY_DIRECT_HTTP = {"direct_ip_http": True, "direct_ip_https": False, "ip_api_exposed": False,
                    "cache_purge_exposed": False, "waf_bypass": False}
_DEFAULT_PORT = {"http": 80, "https": 443}


def _sub(*ips):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}}


def _domain(names=None):
    names = names or {WWW: [WWW_IP], APP: [APP_IP], LEGACY: [LEGACY_IP]}
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": False, "root_domain": APEX},
        "subdomains": list(names),
        "dns": {"domain": {}, "subdomains": {n: _sub(*a) for n, a in names.items()}},
        "port_scan": {"by_ip": {a[0]: {"ip": a[0], "ports": [80], "hostnames": [n]}
                                for n, a in names.items()}},
        "http_probe": {"by_url": {f"http://{n}": {"url": f"http://{n}", "host": n, "ip": a[0],
                                                  "status_code": 200} for n, a in names.items()}},
    }


def _response(url, location=None):
    resp = requests.Response()
    resp.status_code = 302 if location else 200
    resp.url = url
    resp.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    if location:
        resp.headers["Location"] = location
    resp._content = b"<html><body>ok</body></html>"
    resp.encoding = "utf-8"
    return resp


def _run(monkeypatch, recon, redirects, roe=None, resolve=None, enabled=ONLY_DIRECT_HTTP):
    """run_security_checks with every host answering on every port, a 302 for
    each URL in ``redirects``. A call letting requests follow redirects follows
    them here too, each hop recorded. Returns (result, requests sent, pacer slots)."""
    sent, slots = [], []
    resolve = resolve or {}

    def request(self, method, url, *a, allow_redirects=True, **k):
        history = []
        while True:
            sent.append((method.upper(), url))
            resp = _response(url, redirects.get(url))
            if not (allow_redirects and resp.is_redirect):
                resp.history = history
                return resp
            history.append(resp)
            url = urljoin(url, resp.headers["Location"])

    def getaddrinfo(host, *a, **k):
        if host in resolve:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, 0)) for ip in resolve[host]]
        raise socket.gaierror(f"no such name: {host}")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(request_pacer, "acquire", lambda *a, **k: slots.append(1))
    for name in ("collect_reliable_edge_ips", "collect_asn_cdn_ips", "collect_prefix_cdn_ips"):
        monkeypatch.setattr(sc, name, lambda *a, **k: set())
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        result = sc.run_security_checks(recon, enabled, timeout=1, max_workers=1,
                                        roe_excluded_hosts=roe)
    return result, sent, slots


def _finding(result, ip):
    return next(f for f in result["security_checks"]["findings"]
                if f["type"] == "direct_ip_http" and f["matched_ip"] == ip)


def _hosts(sent):
    return {urlsplit(u).hostname for _m, u in sent}


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


@pytest.mark.parametrize("location", [
    pytest.param(f"https://{THIRD}/login", id="third-party"),
    pytest.param(f"http://{METADATA}/latest/meta-data/", id="cloud-metadata"),
    pytest.param("http://10.0.0.5/", id="private-address-the-run-never-resolved"),
])
def test_a_hop_off_the_runs_hosts_is_never_sent(monkeypatch, location):
    result, sent, _slots = _run(monkeypatch, _domain(), {f"http://{WWW_IP}": location})

    assert urlsplit(location).hostname not in _hosts(sent)
    finding = _finding(result, WWW_IP)
    assert finding["redirects"] is True
    assert finding["final_url"] == location
    if finding["redirects_to_hostname"]:
        assert "(1 redirect(s))" in finding["evidence"]
    else:
        assert finding["evidence"] == f"HTTP 302 redirect to {location}"
    # A refused hop is not an outage.
    assert circuit_breaker.host_health.unreachable() == []
    assert circuit_breaker.coverage_report().skipped_hosts == ()


def test_a_chain_follows_the_runs_own_hosts_and_stops_at_the_first_other_one(monkeypatch):
    result, sent, _slots = _run(monkeypatch, _domain(), {
        f"http://{WWW_IP}": f"http://{APP}/",
        f"http://{APP}/": f"http://{APP_IP}/next",
        f"http://{APP_IP}/next": f"https://{THIRD}/login",
    })

    assert ("GET", f"http://{APP}/") in sent
    assert ("GET", f"http://{APP_IP}/next") in sent
    assert THIRD not in _hosts(sent)
    finding = _finding(result, WWW_IP)
    assert finding["final_url"] == f"https://{THIRD}/login"
    assert finding["redirects_to_hostname"] is True
    assert "(3 redirect(s))" in finding["evidence"]


def test_a_hop_onto_a_host_the_roe_excludes_is_never_sent(monkeypatch, capsys):
    """legacy.example.com is one of the run's names, but it resolves into the
    excluded range: the run's admission and the hop's own RoE check refuse it."""
    result, sent, _slots = _run(monkeypatch, _domain(), {f"http://{WWW_IP}": f"http://{LEGACY}/"},
                                roe=[EXCLUDED_RANGE], resolve={LEGACY: [LEGACY_IP], WWW: [WWW_IP]})

    assert {LEGACY, LEGACY_IP}.isdisjoint(_hosts(sent))
    assert _finding(result, WWW_IP)["final_url"] == f"http://{LEGACY}/"
    assert "[-][RoE] security_checks: not sent to" in capsys.readouterr().out


def test_a_hop_onto_an_excluded_address_literal_is_never_sent(monkeypatch):
    result, sent, _slots = _run(monkeypatch, _domain({WWW: [WWW_IP]}),
                                {f"http://{WWW_IP}": f"http://{LEGACY_IP}/"}, roe=[EXCLUDED_RANGE])

    assert LEGACY_IP not in _hosts(sent)
    assert _finding(result, WWW_IP)["final_url"] == f"http://{LEGACY_IP}/"


def test_every_hop_takes_its_own_pacer_slot(monkeypatch):
    _result, sent, slots = _run(monkeypatch, _domain(), {
        f"http://{WWW_IP}": f"http://{APP}/",
        f"http://{APP}/": f"http://{APP_IP}/next",
    })

    assert ("GET", f"http://{APP_IP}/next") in sent
    assert len(slots) == len(sent)


def test_the_runs_admission_rule_does_not_outlive_it(monkeypatch):
    seen = []
    real = sc._follow_admitted_redirects

    def spy(*a, **k):
        seen.append((k.get("admit"), sc._IP_MODE_ADMIT))
        return real(*a, **k)

    monkeypatch.setattr(sc, "_follow_admitted_redirects", spy)
    _run(monkeypatch, _domain(), {f"http://{WWW_IP}": f"http://{APP}/"})

    # The domain walk uses the run's own rule, never IP mode's.
    assert seen and all(admit is not None and ip_admit is None for admit, ip_admit in seen)
    assert sc._DOMAIN_REDIRECT_ADMIT is None
