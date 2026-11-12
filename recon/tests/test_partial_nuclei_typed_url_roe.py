"""A partial Nuclei run scans the URL the operator typed under RoE IP exclusions (R-2, D2).

Seen on the nested lab (domain mode, RoE excluding an address and a name): a
partial Nuclei with only a typed allowed URL and graph targets off scanned
nothing. The log said "No targets found in recon data", and the only RoE
refusal named the project root.

run_vuln_scan admits its targets through the D2 gate, which judges a name on
the addresses the recon dict holds: a name with none is refused while RoE IP or
CIDR entries exist. The partial module put the typed URL into http_probe only,
never its host into DNS, so the gate saw the root (graph off: no address) and
nothing else, and the typed URL itself, on reaching the URL gate, would have
been refused for want of an address too. The run's start already admitted the
typed host on its resolved addresses (filter_partial_user_input); the module now
hands those addresses on, so the gate judges the host on them.

With graph targets off the run scans what the operator typed and nothing else:
the root, which the dict's missing include-root flag used to add (and Nuclei
scanned as http(s)://root with no RoE), is no target; a typed host joins the
dict as a late name does (has_records, resolved by the tool). With graph
targets on and no address rule the dict is unchanged; IP mode is unchanged.

The real partial module, run_vuln_scan, its target builders and the gate run;
DNS, Docker, the Nuclei process and Neo4j are the fakes. Reserved names and
RFC 5737 addresses only.
"""
from __future__ import annotations

import copy
import re
import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402

ROOT = "example.com"
WWW, WWW_IP = "www.example.com", "192.0.2.10"
APP, APP_IP = "app.example.com", "192.0.2.20"          # a graph Subdomain with a BaseURL
NEW, NEW_IP = "new.example.com", "192.0.2.30"          # typed, not in the graph
EDGE, EDGE_IP = "edge.example.com", "198.51.100.62"    # only on the excluded address
MIXED, MIXED_OK = "mixed.example.com", "192.0.2.11"    # one allowed, one excluded address
GHOST = "ghost.example.com"                            # no address at all
SHOP = "shop.example.com"                              # excluded by name

ADDRESSES = {ROOT: ["192.0.2.1"], WWW: [WWW_IP], APP: [APP_IP], NEW: [NEW_IP], EDGE: [EDGE_IP],
             MIXED: [MIXED_OK, EDGE_IP], SHOP: ["192.0.2.40"]}

ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [f"{EDGE_IP}/32", SHOP]}
#: No address rule in force: the gate either is inert or judges names by name only.
NO_ADDRESS_RULE = [
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [f"{EDGE_IP}/32", SHOP]},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [SHOP]},
]
TOKEN = re.compile(r"^[a-z0-9_]{1,64}$")

BASE_SETTINGS = {
    "MITRE_ENABLED": False, "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False,
    "NUCLEI_TAGS": ["cve"], "NUCLEI_DAST_MODE": False, "NUCLEI_AI_TAGS": False,
    "NUCLEI_AI_RESPONSE_FILTER": False, "INCLUDE_ROOT_DOMAIN": False,
}


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


@pytest.fixture
def asked(monkeypatch):
    """Every name looked up, answered from ADDRESSES (anything else: NXDOMAIN)."""
    seen = []

    def getaddrinfo(host, *_a, **_k):
        seen.append(host)
        if host not in ADDRESSES:
            raise socket.gaierror(socket.EAI_NONAME, "unknown name")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, 1, 6, "", (a, 0))
                for a in ADDRESSES[host]]

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    return seen


@pytest.fixture(autouse=True)
def _fake_graph(monkeypatch):
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_vuln_scan.return_value = {}
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)


def _graph_recon() -> dict:
    """What _build_vuln_scan_data_from_graph returns for a project whose graph
    holds APP with its BaseURL (the root left out by scope)."""
    return {
        "domain": ROOT, "domains": [ROOT], "subdomains": [APP],
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {APP: {"ips": {"ipv4": [APP_IP], "ipv6": []}, "has_records": True}}},
        "metadata": {"include_root_domain": False, "roe": dict(ROE)},
        "http_probe": {"by_url": {f"https://{APP}": {"url": f"https://{APP}", "host": APP,
                                                      "status_code": 200, "content_type": "text/html"}}},
        "port_scan": {"by_ip": {}},
        "resource_enum": {"by_base_url": {}, "discovered_urls": []},
    }


def _run(monkeypatch, settings: dict, urls: list, include_graph: bool = False,
         graph_recon: dict = None) -> dict:
    """The partial Nuclei run. Returns {"targets": the URLs Nuclei was handed
    (None when it never ran), "recon": the dict run_vuln_scan received}."""
    from recon.main_recon_modules import vuln_scan
    from recon.partial_recon_modules import vulnerability_scanning as vs

    out = {"targets": None, "recon": None}
    real_build = vuln_scan.build_nuclei_command
    real_run = vuln_scan.run_vuln_scan

    def build(*args, **kwargs):
        out["targets"] = Path(kwargs["targets_file"]).read_text().split()
        return real_build(*args, **kwargs)

    def run_vuln_scan(recon_data, *args, **kwargs):
        out["recon"] = copy.deepcopy(recon_data)
        return real_run(recon_data, *args, **kwargs)

    monkeypatch.setattr(vuln_scan, "build_nuclei_command", build)
    monkeypatch.setattr(vuln_scan, "run_vuln_scan", run_vuln_scan)
    monkeypatch.setattr(vuln_scan, "_execute_nuclei_pass", lambda *_a, **_k: ([], [], 0, 0))
    monkeypatch.setattr(vuln_scan, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vuln_scan, "is_docker_running", lambda: True)
    monkeypatch.setattr(vuln_scan, "pull_nuclei_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(vuln_scan, "ensure_templates_volume", lambda *_a, **_k: True)
    monkeypatch.setattr("helpers.proxy_routing.get_capture_routing", lambda *_a, **_k: (None, None))
    monkeypatch.setattr(vs, "graph_url_fingerprints", lambda *_a, **_k: {})
    if graph_recon is not None:
        monkeypatch.setattr(vs, "_build_vuln_scan_data_from_graph",
                            lambda *_a, **_k: copy.deepcopy(graph_recon))

    vs.run_nuclei({"_settings": dict(BASE_SETTINGS, **settings), "domains": [ROOT], "domain": ROOT,
                   "include_graph_targets": include_graph,
                   "user_targets": {"urls": list(urls), "url_attach_to": None}})
    return out


def _roe_gaps() -> list:
    return [dict(g) for g in circuit_breaker.coverage_report().gaps if g["source"] == "roe_excluded"]


def _hosts(urls) -> set:
    from urllib.parse import urlsplit
    return {urlsplit(u).hostname for u in urls or []}


# --------------------------------------------------------------------------
# The E2E case: graph targets off, one typed allowed URL
# --------------------------------------------------------------------------

def test_graph_off_a_typed_allowed_url_is_scanned(monkeypatch, asked, capsys):
    out = _run(monkeypatch, ROE, [f"https://{WWW}/"])
    log = capsys.readouterr().out
    assert "No targets found in recon data" not in log
    assert out["targets"] == [f"https://{WWW}/"], log


def test_graph_off_the_typed_host_is_judged_on_its_resolved_address(monkeypatch, asked):
    out = _run(monkeypatch, ROE, [f"https://{WWW}/"])
    entry = out["recon"]["dns"]["subdomains"][WWW]
    assert entry["ips"]["ipv4"] == [WWW_IP] and entry["has_records"] is True
    assert asked.count(WWW) == 1


def test_graph_off_a_typed_url_on_an_excluded_address_is_never_scanned(monkeypatch, asked, capsys):
    out = _run(monkeypatch, ROE, [f"https://{EDGE}/", f"https://{MIXED}/", f"https://{WWW}/"])
    assert out["targets"] == [f"https://{WWW}/"]
    refusals = [line for line in capsys.readouterr().out.splitlines() if line.startswith("[-][RoE]")]
    for refused in (EDGE, MIXED, EDGE_IP):
        assert any(refused in line for line in refusals), refused
    gaps = _roe_gaps()
    assert gaps and all(TOKEN.match(g["module"]) and TOKEN.match(g["source"]) for g in gaps)


def test_graph_off_an_unresolvable_typed_host_is_refused_as_not_checked(monkeypatch, asked):
    out = _run(monkeypatch, ROE, [f"https://{GHOST}/", f"https://{WWW}/"])
    assert out["targets"] == [f"https://{WWW}/"]
    assert GHOST in circuit_breaker.coverage_report().skipped_hostnames()


# --------------------------------------------------------------------------
# Graph targets on: a typed host the graph does not hold
# --------------------------------------------------------------------------

def test_graph_on_a_typed_url_on_a_new_host_is_scanned_with_the_graphs(monkeypatch, asked):
    out = _run(monkeypatch, ROE, [f"https://{NEW}/login"], include_graph=True,
               graph_recon=_graph_recon())
    assert set(out["targets"]) == {f"https://{APP}", f"https://{NEW}/login"}


def test_graph_on_a_typed_host_the_graph_resolved_is_not_looked_up_again(monkeypatch, asked):
    out = _run(monkeypatch, ROE, [f"https://{APP}/admin"], include_graph=True,
               graph_recon=_graph_recon())
    assert f"https://{APP}/admin" in out["targets"]
    assert APP not in asked
    assert out["recon"]["dns"]["subdomains"][APP]["ips"]["ipv4"] == [APP_IP]


# --------------------------------------------------------------------------
# Unchanged where no address rule is in force, and in IP mode
# --------------------------------------------------------------------------

@pytest.mark.parametrize("settings", NO_ADDRESS_RULE, ids=["no_keys", "empty", "off", "names_only"])
def test_graph_off_without_an_address_rule_only_the_typed_url_and_no_lookup(monkeypatch, asked, settings):
    # Graph targets off scans what the operator typed, never the root the
    # legacy include-root default used to add (http(s)://root): Nuclei
    # resolves the typed host itself, so no lookup is made here.
    out = _run(monkeypatch, settings, [f"https://{WWW}/"])
    assert out["targets"] == [f"https://{WWW}/"]
    assert WWW not in asked
    assert out["recon"]["dns"]["subdomains"] == {
        WWW: {"ips": {"ipv4": [], "ipv6": []}, "has_records": True}}


def test_graph_off_the_root_is_neither_scanned_nor_refused(monkeypatch, asked):
    out = _run(monkeypatch, ROE, [f"https://{WWW}/"])
    assert _hosts(out["targets"]) == {WWW}
    assert ROOT not in circuit_breaker.coverage_report().skipped_hostnames()
    assert ROOT not in asked


@pytest.mark.parametrize("settings", [{}, ROE], ids=["no_roe", "roe"])
def test_graph_off_a_typed_url_on_the_root_itself_is_scanned(monkeypatch, asked, settings):
    out = _run(monkeypatch, settings, [f"https://{ROOT}/"])
    assert out["targets"] == [f"https://{ROOT}/"]


@pytest.mark.parametrize("settings", [{}, ROE], ids=["no_roe", "roe"])
def test_graph_off_a_typed_url_on_an_address_is_scanned(monkeypatch, asked, settings):
    # With the root out, a typed address needs its own entry: dns.domain's
    # addresses count only with the root.
    out = _run(monkeypatch, settings, ["https://192.0.2.50:8443/"])
    assert out["targets"] == ["https://192.0.2.50:8443/"]


def test_graph_off_a_typed_url_on_an_excluded_address_is_refused(monkeypatch, asked):
    out = _run(monkeypatch, ROE, [f"https://{EDGE_IP}/", f"https://{WWW}/"])
    assert out["targets"] == [f"https://{WWW}/"]


def test_graph_on_without_an_address_rule_the_dict_is_unchanged(monkeypatch, asked):
    graph = _graph_recon()
    del graph["metadata"]["roe"]
    out = _run(monkeypatch, {}, [f"https://{NEW}/login"], include_graph=True, graph_recon=graph)
    assert set(out["targets"]) == {f"https://{APP}", f"https://{NEW}/login"}
    assert NEW not in asked
    assert out["recon"]["dns"] == graph["dns"]
    # domain_batch is the module's own stamp for every run.
    assert {k: v for k, v in out["recon"]["metadata"].items() if k != "domain_batch"} == graph["metadata"]


def test_ip_mode_typed_hosts_are_not_resolved_here(monkeypatch, asked):
    # IP mode admits a typed name only through the hostname rule's pinned
    # answer (ip_hostname_scope); this module resolves nothing of its own.
    from recon.main_recon_modules import vuln_scan
    from recon.partial_recon_modules import vulnerability_scanning as vs

    def stamp(recon_data, settings=None):
        recon_data.setdefault("metadata", {}).update(ip_mode=True, expanded_ips=[WWW_IP])
        return recon_data

    seen = {}
    monkeypatch.setattr(vs, "ip_mode_recon", stamp)
    monkeypatch.setattr(vs, "graph_url_fingerprints", lambda *_a, **_k: {})
    monkeypatch.setattr(vuln_scan, "run_vuln_scan",
                        lambda rd, **_k: seen.setdefault("recon", copy.deepcopy(rd)) or rd)
    vs.run_nuclei({"_settings": dict(BASE_SETTINGS, **ROE), "domains": [ROOT], "domain": ROOT,
                   "include_graph_targets": False,
                   "user_targets": {"urls": [f"https://{WWW}/"], "url_attach_to": None}})
    assert WWW not in asked
    assert seen["recon"]["dns"]["subdomains"] == {}
    assert "include_root_domain" not in seen["recon"]["metadata"]
