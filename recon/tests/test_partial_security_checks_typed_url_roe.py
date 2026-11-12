"""A partial SecurityChecks run checks the URL the operator typed under RoE IP exclusions (R-2, D2).

Seen on the nested lab (domain mode, RoE excluding an address and a name): a
partial SecurityChecks run with only a typed allowed URL and graph targets off
checked nothing. The log said "Targets: 0 hostnames, 0 IPs", and the only RoE
refusal was the project root, "not sent to 1 name(s) with no known address".

The hostname checks take their hosts from the recon dict's DNS block and admit
them through the D2 gate, which refuses a name with no known address while RoE
IP or CIDR entries exist. The module put the typed URL into http_probe only,
never its host into DNS, so the checks saw the root alone (graph off: no
address, offered by the include-root flag's legacy default) and the gate
refused it. With no RoE the root was the only hostname too, and with the
typed URL as the run's only live-port evidence it was never probed either.

The same rule as the partial Nuclei fix (05c52e8a, _typed_url_hosts_in_dns):
with graph targets off the run checks what was typed and nothing else (the
root is no target, a typed host joins DNS with has_records alone, a typed
address is its own entry); under RoE IP or CIDR entries a typed host the dict
holds no address for is resolved once, so the gate judges its real addresses.
With graph targets on and no address rule the dict is unchanged; IP mode is
unchanged.

The real partial module, run_security_checks, its target extraction and the
gate run; DNS, requests' Session, sockets and Neo4j are the fakes, every port
answering, so a request that is not sent is one the checks chose not to send.
Reserved names and RFC 5737 addresses only.
"""
from __future__ import annotations

import copy
import socket
import sys
import time as _time
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest
import requests

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import security_checks as sc  # noqa: E402
from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402

ROOT, ROOT_IP = "example.com", "192.0.2.1"
WWW, WWW_IP = "www.example.com", "192.0.2.10"
APP, APP_IP = "app.example.com", "192.0.2.20"          # a graph Subdomain with a BaseURL
NEW, NEW_IP = "new.example.com", "192.0.2.30"          # typed, not in the graph
EDGE, EDGE_IP = "edge.example.com", "198.51.100.62"    # only on the excluded address
MIXED, MIXED_OK = "mixed.example.com", "192.0.2.11"    # one allowed, one excluded address
GHOST = "ghost.example.com"                            # no address at all
SHOP = "shop.example.com"                              # excluded by name
BARE = "192.0.2.50"                                    # a typed address

ADDRESSES = {ROOT: [ROOT_IP], WWW: [WWW_IP], APP: [APP_IP], NEW: [NEW_IP], EDGE: [EDGE_IP],
             MIXED: [MIXED_OK, EDGE_IP], SHOP: ["192.0.2.40"]}

ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [f"{EDGE_IP}/32", SHOP]}
#: No address rule in force: the gate either is inert or judges names by name only.
NO_ADDRESS_RULE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [f"{EDGE_IP}/32", SHOP]},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [SHOP]},
]
_NO_ADDRESS_RULE_IDS = ["no_keys", "empty", "off", "names_only"]

# The org's mail and zone checks query DNS by themselves and do not depend on
# the typed hosts: off, so every lookup here is the module's own.
_NO_ORG_DNS = {f"SECURITY_CHECK_{t.upper()}": False
               for t in ("spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer")}
_DEFAULT_PORT = {"http": 80, "https": 443}
_NO_ADDRESS_LINE = "name(s) with no known address"


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})
    client = mock.MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = mock.MagicMock(return_value=client)
    client.__exit__ = mock.MagicMock(return_value=False)
    client.update_graph_from_vuln_scan.return_value = {}
    graph_db = mock.MagicMock()
    graph_db.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", graph_db)
    yield
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})


def _response(url):
    resp = requests.Response()
    resp.status_code = 200
    resp.url = url
    resp.headers = requests.structures.CaseInsensitiveDict({"Content-Type": "text/html"})
    resp._content = b"<html><body>ok</body></html>"
    resp.encoding = "utf-8"
    return resp


def _graph_recon(roe: dict = None) -> dict:
    """What _build_vuln_scan_data_from_graph returns for a project whose graph
    holds APP with its BaseURL (the root left out by scope)."""
    recon = {
        "domain": ROOT, "domains": [ROOT], "subdomains": [APP],
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {APP: {"ips": {"ipv4": [APP_IP], "ipv6": []}, "has_records": True}}},
        "metadata": {"include_root_domain": False},
        "http_probe": {"by_url": {f"https://{APP}": {"url": f"https://{APP}", "host": APP,
                                                      "status_code": 200, "content_type": "text/html"}}},
        "port_scan": {"by_ip": {}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
    }
    if roe:
        recon["metadata"]["roe"] = dict(roe)
    return recon


def _run(monkeypatch, settings: dict, urls=(), ips=(), include_graph: bool = False,
         graph_recon: dict = None, checks=None) -> dict:
    """The partial SecurityChecks run. Returns {"sent": requests as (method,
    url, Host header), "opened": sockets as (host, port), "resolved": the names
    the module looked up, "recon": the dict run_security_checks received}."""
    import recon.helpers as recon_helpers
    from recon.partial_recon_modules import vulnerability_scanning as vs

    out = {"sent": [], "opened": [], "resolved": [], "recon": None}

    def request(self, method, url, *a, allow_redirects=True, **k):
        out["sent"].append((method.upper(), url, ((k.get("headers") or {}).get("Host") or "").lower()))
        return _response(url)

    def connect(address, *a, **k):
        out["opened"].append((address[0], address[1]))
        raise ConnectionRefusedError("no TLS here")

    def getaddrinfo(host, *a, **k):
        raise socket.gaierror(f"no resolver in this test: {host}")

    def resolve(host):
        out["resolved"].append(host)
        found = ADDRESSES.get(host, [])
        return {"ipv4": [a for a in found if ":" not in a], "ipv6": [a for a in found if ":" in a]}

    real_checks = checks or recon_helpers.run_security_checks

    def run_security_checks(recon_data, *args, **kwargs):
        out["recon"] = copy.deepcopy(recon_data)
        return real_checks(recon_data, *args, **kwargs)

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr(sc.socket, "create_connection", connect)
    monkeypatch.setattr(sc.socket, "getaddrinfo", getaddrinfo)
    for name in ("collect_reliable_edge_ips", "collect_asn_cdn_ips", "collect_prefix_cdn_ips"):
        monkeypatch.setattr(sc, name, lambda *a, **k: set())
    monkeypatch.setattr(vs, "_resolve_hostname", resolve)
    monkeypatch.setattr(recon_helpers, "run_security_checks", run_security_checks)
    if graph_recon is not None:
        monkeypatch.setattr(vs, "_build_vuln_scan_data_from_graph",
                            lambda *_a, **_k: copy.deepcopy(graph_recon))
        monkeypatch.setattr(vs, "graph_open_ports", lambda *_a, **_k: {})

    run_settings = {"SUBDOMAIN_LIST": ["."], **_NO_ORG_DNS, **settings}
    # What partial_recon._prepare_scope does before any module runs.
    partial_helpers.set_run_roe(run_settings)
    config = {"_settings": run_settings, "domains": [ROOT], "domain": ROOT,
              "include_graph_targets": include_graph,
              "user_targets": {"urls": list(urls), "url_attach_to": None, "ips": list(ips)}}
    with mock.patch.object(sc, "time") as fake_time:
        fake_time.time.side_effect = _time.time
        fake_time.monotonic.side_effect = _time.monotonic
        fake_time.sleep = lambda *_a, **_k: None
        vs.run_security_checks_partial(config)
    return out


def _reached(out, host) -> list:
    return ([u for _m, u, h in out["sent"] if urlparse(u).hostname == host or h == host]
            + [f"socket {h}:{p}" for h, p in out["opened"] if h == host])


def _checked_by_name(out, host) -> bool:
    """The header, cookie and CSP checks fetched https://host/."""
    return ("GET", f"https://{host}/", "") in out["sent"]


def _refusal_lines(log: str) -> list:
    return [line for line in log.splitlines() if line.startswith("[-][RoE]")]


# --------------------------------------------------------------------------
# The E2E case: graph targets off, one typed allowed URL
# --------------------------------------------------------------------------

def test_graph_off_a_typed_allowed_url_is_checked(monkeypatch, capsys):
    out = _run(monkeypatch, ROE, urls=[f"https://{WWW}/"])
    log = capsys.readouterr().out
    assert "Targets: 0 hostnames, 0 IPs" not in log, log
    assert _NO_ADDRESS_LINE not in log, log
    assert _checked_by_name(out, WWW), out["sent"]
    assert (WWW, 443) in out["opened"]                         # TLS expiry


def test_graph_off_the_typed_host_is_judged_on_its_resolved_address(monkeypatch):
    out = _run(monkeypatch, ROE, urls=[f"https://{WWW}/"])
    entry = out["recon"]["dns"]["subdomains"][WWW]
    assert entry["ips"]["ipv4"] == [WWW_IP] and entry["has_records"] is True
    assert out["resolved"].count(WWW) == 1


def test_graph_off_the_root_is_neither_checked_nor_refused(monkeypatch, capsys):
    out = _run(monkeypatch, ROE, urls=[f"https://{WWW}/"])
    assert _reached(out, ROOT) == []
    assert not any(ROOT + ":" in line or line.endswith(ROOT) for line in _refusal_lines(capsys.readouterr().out))
    report = circuit_breaker.coverage_report()
    assert ROOT not in report.skipped_hostnames()
    assert ROOT not in report.keep_hostnames("security_check")
    assert ROOT not in out["resolved"]


def test_graph_off_a_typed_url_on_an_excluded_address_is_never_checked(monkeypatch, capsys):
    out = _run(monkeypatch, ROE, urls=[f"https://{EDGE}/", f"https://{MIXED}/", f"https://{SHOP}/",
                                       f"https://{WWW}/"])
    for host in (EDGE, MIXED, SHOP, EDGE_IP):
        assert _reached(out, host) == [], f"{host} was reached"
    assert _checked_by_name(out, WWW)
    refusals = _refusal_lines(capsys.readouterr().out)
    for refused in (EDGE, MIXED, SHOP):
        assert any(refused in line for line in refusals), refused


def test_graph_off_an_unresolvable_typed_host_is_refused_as_not_checked(monkeypatch):
    out = _run(monkeypatch, ROE, urls=[f"https://{GHOST}/", f"https://{WWW}/"])
    assert _reached(out, GHOST) == []
    assert _checked_by_name(out, WWW)
    assert GHOST in circuit_breaker.coverage_report().skipped_hostnames()


def test_graph_off_a_typed_url_on_an_excluded_address_literal_is_refused(monkeypatch):
    out = _run(monkeypatch, ROE, urls=[f"https://{EDGE_IP}/", f"https://{WWW}/"])
    assert _reached(out, EDGE_IP) == []
    assert _checked_by_name(out, WWW)


# --------------------------------------------------------------------------
# Graph targets off with no address rule: what was typed, never the root
# --------------------------------------------------------------------------

@pytest.mark.parametrize("settings", NO_ADDRESS_RULE, ids=_NO_ADDRESS_RULE_IDS)
def test_graph_off_without_an_address_rule_only_the_typed_host_and_no_lookup(monkeypatch, settings):
    # The legacy include-root default made the root the run's only hostname:
    # with the typed URL as the only live-port evidence it was left unprobed
    # (kept as not checked) and the typed host was never checked at all.
    out = _run(monkeypatch, settings, urls=[f"https://{WWW}/"])
    assert _checked_by_name(out, WWW)
    assert _reached(out, ROOT) == []
    assert ROOT not in circuit_breaker.coverage_report().keep_hostnames("security_check")
    assert out["resolved"] == []
    assert out["recon"]["dns"]["subdomains"] == {
        WWW: {"ips": {"ipv4": [], "ipv6": []}, "has_records": True}}


@pytest.mark.parametrize("settings", [{}, ROE], ids=["no_roe", "roe"])
def test_graph_off_a_typed_url_on_the_root_itself_is_checked(monkeypatch, settings):
    out = _run(monkeypatch, settings, urls=[f"https://{ROOT}/"])
    assert _checked_by_name(out, ROOT)


@pytest.mark.parametrize("settings", [{}, ROE], ids=["no_roe", "roe"])
def test_graph_off_a_typed_url_on_an_address_is_checked(monkeypatch, settings):
    # With the root out, a typed address needs its own entry: dns.domain's
    # addresses count only with the root.
    out = _run(monkeypatch, settings, urls=[f"https://{BARE}/"])
    assert ("GET", f"https://{BARE}", "") in out["sent"]       # direct_ip_https
    assert _checked_by_name(out, BARE)


@pytest.mark.parametrize("settings", [{}, ROE], ids=["no_roe", "roe"])
def test_graph_off_a_typed_ip_is_checked_and_the_root_is_not(monkeypatch, settings):
    # A typed IP was the root's address (dns.domain): the root, never typed,
    # was checked by name, and under RoE judged on an address it may not have.
    out = _run(monkeypatch, settings, ips=[BARE])
    assert ("GET", f"http://{BARE}", "") in out["sent"]        # direct_ip_http
    assert ("GET", f"https://{BARE}", "") in out["sent"]       # direct_ip_https
    assert _reached(out, ROOT) == []


# --------------------------------------------------------------------------
# Graph targets on
# --------------------------------------------------------------------------

def test_graph_on_a_typed_url_on_a_new_host_is_checked_under_an_address_rule(monkeypatch, capsys):
    out = _run(monkeypatch, ROE, urls=[f"https://{NEW}/login"], include_graph=True,
               graph_recon=_graph_recon(ROE))
    assert _checked_by_name(out, NEW)
    assert _checked_by_name(out, APP)
    assert out["resolved"].count(NEW) == 1
    assert _NO_ADDRESS_LINE not in capsys.readouterr().out


def test_graph_on_a_typed_host_the_graph_resolved_is_not_looked_up_again(monkeypatch):
    out = _run(monkeypatch, ROE, urls=[f"https://{APP}/admin"], include_graph=True,
               graph_recon=_graph_recon(ROE))
    assert APP not in out["resolved"]
    assert out["recon"]["dns"]["subdomains"][APP]["ips"]["ipv4"] == [APP_IP]


@pytest.mark.parametrize("settings", NO_ADDRESS_RULE, ids=_NO_ADDRESS_RULE_IDS)
def test_graph_on_without_an_address_rule_the_dict_is_unchanged(monkeypatch, settings):
    graph = _graph_recon()
    out = _run(monkeypatch, settings, urls=[f"https://{NEW}/login"], ips=[BARE],
               include_graph=True, graph_recon=graph,
               checks=lambda *_a, **_k: {"security_checks": {"findings": []}})
    assert out["resolved"] == []
    expected_dns = copy.deepcopy(graph["dns"])
    expected_dns["domain"]["ips"]["ipv4"].append(BARE)
    expected_dns["domain"]["has_records"] = True
    assert out["recon"]["dns"] == expected_dns
    assert out["recon"]["metadata"] == {**graph["metadata"], "typed_hosts": [BARE]}
    assert set(out["recon"]["http_probe"]["by_url"]) == {f"https://{APP}", f"https://{NEW}/login"}


# --------------------------------------------------------------------------
# IP mode: unchanged
# --------------------------------------------------------------------------

def test_ip_mode_typed_hosts_are_not_resolved_here(monkeypatch):
    # IP mode admits a typed name only through the hostname rule's pinned
    # answer (ip_hostname_scope); this module resolves nothing of its own.
    from recon.partial_recon_modules import vulnerability_scanning as vs

    def stamp(recon_data, settings=None):
        recon_data.setdefault("metadata", {}).update(ip_mode=True, expanded_ips=[WWW_IP, BARE])
        return recon_data

    monkeypatch.setattr(vs, "ip_mode_recon", stamp)
    out = _run(monkeypatch, ROE, urls=[f"https://{WWW}/"], ips=[BARE],
               checks=lambda *_a, **_k: {"security_checks": {"findings": []}})
    assert out["resolved"] == []
    assert out["recon"]["dns"]["subdomains"] == {}
    assert out["recon"]["dns"]["domain"]["ips"]["ipv4"] == [BARE]
    assert "include_root_domain" not in out["recon"]["metadata"]
    assert "typed_hosts" not in out["recon"]["metadata"]
