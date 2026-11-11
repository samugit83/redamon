"""Every request the security checks send to an IPv6 IP-mode target is a valid URL.

In IP mode the hostname, header and TLS checks are handed the target addresses
as IP literals (B-13). An IPv6 literal written into a URL without brackets
(``https://2001:db8::1``) is no URL: requests raises InvalidURL, the check tests
nothing, and the host-health record counts a failure for a live host. This
sweep runs every check on an IPv6 IP-mode recon dict with the network faked and
fails on the first request whose host is not a bracketed IPv6 literal, so a new
unbracketed URL site fails here.

Documentation addresses (RFC 3849) only.
"""
import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlsplit

import pytest
import requests

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402

V6 = "2001:db8::1"


class _Every(dict):
    """Every check switched on, whatever its name."""

    def get(self, key, default=None):
        return True


def _recon():
    return {
        "domain": "ip-targets.p1",
        "metadata": {"ip_mode": True, "expanded_ips": [V6], "root_domain": "ip-targets.p1",
                     "scope_mode": "exact", "include_root_domain": False},
        "subdomains": ["2001-db8--1"],
        "dns": {"domain": {}, "subdomains": {"2001-db8--1": {
            "has_records": True, "is_mock": True, "actual_ip": V6, "records": {},
            "ips": {"ipv4": [], "ipv6": [V6]}}}},
        "port_scan": {
            "by_ip": {V6: {"ip": V6, "ports": [22, 80, 443, 6379, 8080, 9200], "hostnames": []}},
            "by_host": {V6: {"host": V6, "ip": V6, "ports": [22, 80, 443, 6379, 8080, 9200],
                             "port_details": [{"port": p, "service": ""}
                                              for p in (22, 80, 443, 6379, 8080, 9200)]}},
        },
        "http_probe": {"by_url": {f"https://[{V6}]": {
            "url": f"https://[{V6}]", "host": V6, "ip": V6, "status_code": 200,
            "headers": {"server": "nginx"}, "title": "Login"}}},
    }


def _response(url):
    resp = requests.Response()
    resp.status_code = 200
    resp.url = url
    resp.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    resp._content = b"<html><form action='http://x/login' method='post'>" \
                    b"<input type='password' name='p'></form></html>"
    resp.encoding = "utf-8"
    return resp


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def test_every_request_to_an_ipv6_target_has_a_bracketed_host(monkeypatch):
    sent = []

    def request(self, method, url, *a, **k):
        sent.append(url)
        return _response(url)

    def no_socket(*_a, **_k):
        raise OSError("no network in a unit test")

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(sc.socket, "create_connection", no_socket)
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = __import__("time").time
        fake_time.monotonic.side_effect = __import__("time").monotonic
        fake_time.sleep = lambda *_a, **_k: None
        sc.run_security_checks(_recon(), _Every(), timeout=1, max_workers=2)

    # Third-party lookups (the CDN prefix lists) are not target traffic.
    to_target = [u for u in sent if "2001:db8" in urlsplit(u).netloc]
    assert to_target, "no check sent a request to the target"
    bad = []
    for url in to_target:
        parts = urlsplit(url)
        try:
            parts.port
        except ValueError:
            bad.append(url)
            continue
        if parts.hostname != V6 or not parts.netloc.rpartition("@")[2].startswith(f"[{V6}]"):
            bad.append(url)
    assert bad == []
    # The header checks were among the senders (B-13: they used to get no host).
    assert any(urlsplit(u).path in ("", "/") for u in to_target)
