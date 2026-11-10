"""Characterisation tests: the scope leaks of an IP-mode partial recon run.

A partial run reads its targets back from the graph a full IP-mode run wrote.
That graph holds, under the synthetic Domain ip-targets.<pid>, the placeholder
Subdomain of each listed address AND the PTR name of a listed address with its
forward A record (B-01 writes it with a source-less RESOLVES_TO, so partial
recon reads it as current DNS). The fixture graph below is that state:

    ip-targets.<pid>
      203-0-113-2      -> 203.0.113.2    placeholder of a target
      www.example.com  -> 198.51.100.7   PTR of 203.0.113.1, an address in no target list
    BaseURLs: http://203.0.113.2, https://www.example.com, https://198.51.100.7

Each test states what IP-mode partial recon MUST do and is marked
``xfail(strict=True)`` with the plan's bug id (B-19 .. B-23), so the fix must
remove the marker. The one plain test pins B-19's DNS-only sub-item, already
fixed on master. The name-only tools (SubdomainDiscovery, Urlscan,
OriginDiscovery) must be refused with the run-report reason IP_MODE_REFUSAL.
Everything runs the real code (_prepare_scope, the graph builders, the module
entry points, partial_recon.main); Neo4j, HTTP, DNS and the tool runners are
fakes.

Only documentation addresses (RFC 5737) and reserved names are used.
"""
from __future__ import annotations

import base64
import json
import os
import sys
import tempfile
import types
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# cuid-shaped, so the synthetic root looks exactly like a real one.
PID = "cmipmodeleak0000000000002"
ROOT = f"ip-targets.{PID}"
TARGET_IPS = ["203.0.113.0/30", "203.0.113.9"]
# The full pipeline's expansion of TARGET_IPS (network.hosts() for a CIDR).
TARGETS = ["203.0.113.1", "203.0.113.2", "203.0.113.9"]
TYPED = "203.0.113.9"
PLACEHOLDER = "203-0-113-2"
PTR_NAME = "www.example.com"
FOREIGN = "198.51.100.7"

SETTINGS = {"IP_MODE": True, "TARGET_IPS": list(TARGET_IPS), "TARGET_DOMAIN": "",
            "DOMAIN_BATCH_MODE": False, "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": []}

GRAPH_SUBDOMAINS = [
    # (subdomain, address, open ports)
    (PLACEHOLDER, "203.0.113.2", [80]),
    (PTR_NAME, FOREIGN, [443]),
]
GRAPH_BASEURLS = [
    # (url, host)
    ("http://203.0.113.2", "203.0.113.2"),
    (f"https://{PTR_NAME}", PTR_NAME),
    (f"https://{FOREIGN}", FOREIGN),
]


class _Result(list):
    def single(self):
        return self[0] if self else None


def _ports(ports):
    return [{"number": p, "protocol": "tcp"} for p in ports]


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        rows = _Result()
        domains = [str(d).lower() for d in params.get("domains") or []]
        if "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": [s for s, _, _ in GRAPH_SUBDOMAINS] if ROOT in domains else []})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            if ROOT in domains:
                for sub, ip, ports in GRAPH_SUBDOMAINS:
                    rows.append({"root": ROOT, "subdomain": sub, "address": ip, "ip": ip,
                                 "version": "ipv4", "ports": _ports(ports),
                                 "is_cdn": None, "cdn_name": None, "asn": None})
        elif "RETURN d.name AS name" in cypher:
            rows.append({"name": ROOT})
        elif "co_hosted_vhost_hosts" in cypher:
            rows.append({"co_hosted_vhost_hosts": []})
        elif "MATCH (b:BaseURL" in cypher and "AS status_code" in cypher:
            for url, host in GRAPH_BASEURLS:
                rows.append({"url": url, "host": host, "status_code": 200, "content_type": "text/html",
                             "is_cdn": False, "cdn": None, "asn": None, "server": None,
                             "title": None, "final_url": None, "cname": None, "cert": None})
        elif "ai_interface_type IS NOT NULL" in cypher:
            rows.append({"base_url": "http://203.0.113.2", "path": "/v1/chat/completions",
                         "method": "POST", "iface": "openai-compatible", "ai_fw": False,
                         "declared_only": False})
        elif "RETURN e.baseurl AS baseurl, e.path AS path, e.method AS method" in cypher:
            rows.append({"baseurl": "http://203.0.113.2", "path": "/v1/chat/completions",
                         "method": "POST"})
        elif "HAS_PORT]->(p:Port)" in cypher and "ip.address AS ip" in cypher:
            for _sub, ip, ports in GRAPH_SUBDOMAINS:
                rows.extend({"ip": ip, "port": p} for p in ports)
        return rows


class _Client:
    calls: list = []
    # (writer name, args, kwargs): the recon dict a module hands the graph.
    writes: list = []

    def __init__(self, *_a, **_k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return True

    def close(self):
        pass

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda **_k: _Session(_Client.calls)
        return driver

    def __getattr__(self, name):
        # Every writer (update_graph_from_*, create_user_input_node, ...) is a no-op.
        def write(*args, **kwargs):
            _Client.writes.append((name, args, kwargs))
            return {}
        return write


class _Captured(BaseException):
    """Escapes the modules' own `except Exception` once the input is captured."""


@pytest.fixture
def graph(monkeypatch):
    _Client.calls = []
    _Client.writes = []
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr("graph_db.neo4j_client.Neo4jClient", _Client)
    return _Client.calls


def _prepared(tool_id: str, settings=None, **config) -> dict:
    """The config a module receives: the real _prepare_scope in IP mode."""
    import recon.partial_recon as pr
    cfg = {"tool_id": tool_id, "domains": [ROOT], "include_graph_targets": True, **config}
    pr._prepare_scope(cfg, dict(settings or SETTINGS), PID)
    return cfg


def _writer_input(writer: str):
    """The recon dict the last call of `writer` received, or None."""
    for name, args, kwargs in reversed(_Client.writes):
        if name == writer:
            return kwargs.get("recon_data") or (args[0] if args else None)
    return None


def _dispatch(tool_id: str, config: dict):
    import recon.partial_recon as pr
    return pr._dispatch(tool_id, config)


def _capture(monkeypatch, module_name: str, attr: str, arg=0):
    """Replace a scan function with one that records its recon_data and stops."""
    import importlib
    module = importlib.import_module(module_name)
    seen = {}

    def capture(*args, **kwargs):
        seen["data"] = args[arg] if len(args) > arg else (
            kwargs.get("recon_data") or kwargs.get("combined_result"))
        raise _Captured

    monkeypatch.setattr(module, attr, capture)
    return seen


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def _outside(values) -> list:
    return sorted({str(v) for v in values} - set(TARGETS))


def _recon_ips(recon_data: dict) -> set:
    dns = recon_data.get("dns") or {}
    ips = set()
    for entry in [dns.get("domain") or {}, *((dns.get("subdomains") or {}).values())]:
        for bucket in ("ipv4", "ipv6"):
            ips.update(((entry or {}).get("ips") or {}).get(bucket) or [])
    port_scan = recon_data.get("port_scan") or {}
    ips.update(port_scan.get("by_ip") or {})
    ips.update(h.get("ip") for h in (port_scan.get("by_host") or {}).values() if h.get("ip"))
    return {ip for ip in ips if ip}


@pytest.fixture
def doc_ranges_public(monkeypatch):
    """Documentation ranges are "private" to Python's ipaddress, so the OSINT
    modules' is_non_routable_ip filter would drop every address before an API
    call. Here they stand in for public addresses."""
    import ipaddress
    import recon.main_recon_modules.ip_filter as ip_filter
    nets = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]
    real = ip_filter.is_non_routable_ip

    def routable_doc(ip_str):
        try:
            addr = ipaddress.ip_address(ip_str)
        except ValueError:
            return real(ip_str)
        return False if any(addr in n for n in nets if n.version == addr.version) else real(ip_str)

    monkeypatch.setattr(ip_filter, "is_non_routable_ip", routable_doc)


# ---------------------------------------------------------------------------
# B-19 / B-23: the recon dict every builder and module hands its scanner
# ---------------------------------------------------------------------------

_TYPED_URL = {"include_graph_targets": False, "user_targets": {"urls": [f"http://{TYPED}/app"]}}
_TYPED_JS = {"include_graph_targets": False, "user_targets": {"urls": [f"http://{TYPED}/static/app.js"]}}
# Typed inputs only, so each module builds its recon dict itself (the graph
# path goes through a builder, checked separately).
_TYPED = {"include_graph_targets": False,
          "user_targets": {"ips": [TYPED], "urls": [f"http://{TYPED}/app"]}}
_CRAWL = ("recon.partial_recon_modules.web_crawling", "extract_targets_from_recon", 0, _TYPED)
# A module name of None: the recon dict is the graph writer's input.
_WRITER = (None, "update_graph_from_resource_enum", 0, _TYPED)

SWEEP_SETTINGS = dict(SETTINGS, CENSYS_ENABLED=True, CENSYS_API_TOKEN="synthetic-key-0000",
                      GAU_VERIFY_URLS=False, GAU_DETECT_METHODS=False)

# Every partial branch that builds its own recon dict instead of calling a
# builder: tool_id -> (module of the scanner it calls, scanner name, argument,
# config). The scanner is replaced by a capture; Gau and ParamSpider are
# covered by test_partial_archive_tools_never_receive_placeholder_root.
# SubdomainTakeover is absent: its own dict (vulnerability_scanning.py) gets
# only typed hostnames, which IP mode refuses, so it exits before its
# scanner; its graph path is _build_vuln_scan_data_from_graph, checked above.
SELF_BUILT = {
    "Naabu": ("recon.main_recon_modules.port_scan", "run_port_scan", 0, _TYPED),
    "Masscan": ("recon.main_recon_modules.masscan_scan", "run_masscan_scan", 0, _TYPED),
    "Nmap": ("recon.main_recon_modules.nmap_scan", "run_nmap_scan", 0,
             {"include_graph_targets": False,
              "user_targets": {"ips": [TYPED], "ports": [443]}}),
    "Tlsx": ("recon.main_recon_modules.tls_scan", "run_tlsx_enrichment", 0, _TYPED),
    "Httpx": ("recon.main_recon_modules.http_probe", "run_http_probe", 0, _TYPED),
    "Katana": _CRAWL,
    "Hakrawler": _CRAWL,
    "ZapAjaxSpider": _CRAWL,
    "Ffuf": _CRAWL,
    "Kiterunner": ("recon.partial_recon_modules.parameter_discovery",
                   "extract_targets_from_recon", 0, _TYPED),
    "Jsluice": _WRITER,
    "Arjun": _WRITER,
    "Nuclei": ("recon.main_recon_modules.vuln_scan", "run_vuln_scan", 0, _TYPED),
    "SecurityChecks": ("recon.helpers", "run_security_checks", 0, _TYPED),
    "VhostSni": ("recon.main_recon_modules.vhost_sni_enum", "run_vhost_sni_enrichment", 0, _TYPED),
    "Shodan": ("recon.main_recon_modules.shodan_enrich", "run_shodan_enrichment", 0, _TYPED),
    "OsintEnrichment": ("recon.main_recon_modules.censys_enrich",
                        "run_censys_enrichment_isolated", 0, _TYPED),
    "Uncover": ("recon.main_recon_modules.uncover_enrich", "run_uncover_expansion", 0, {}),
    "GraphqlScan": ("recon.graphql_scan", "run_graphql_scan", 0, _TYPED_URL),
    "WebCachePoison": ("recon.cache_scan", "run_cache_scan", 0, _TYPED_URL),
    "SerializedScan": ("recon.serialized_scan", "run_serialized_scan", 0, _TYPED_URL),
    "RouteExposure": ("recon.route_exposure", "run_route_exposure", 0, _TYPED_URL),
    "JsRecon": ("recon.main_recon_modules.js_recon", "run_js_recon", 0, _TYPED_JS),
    "SupplyChainRecon": ("recon.main_recon_modules.js_recon", "run_js_recon", 0, _TYPED_JS),
    "OpenAPI": ("recon.helpers.openapi.discovery", "run_openapi_discovery", 0,
                {"include_graph_targets": False,
                 "user_targets": {"urls": [f"http://{TYPED}/openapi.json"]}}),
    "AiSurfaceRecon": ("recon.main_recon_modules.ai_surface_recon", "run_ai_surface_recon", 0, {}),
    "EndpointAiClassifier": ("recon.main_recon_modules.resource_enum",
                             "_annotate_ai_endpoint_classifier", 2, {}),
}


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-19/B-23: no partial builder sets metadata.ip_mode, and expanded_ips holds raw CIDRs")
def test_partial_builders_set_ip_mode_metadata(graph, monkeypatch):
    from recon.partial_recon_modules import graph_builders as gb
    wrong = {}

    def check(name, recon_data):
        metadata = (recon_data or {}).get("metadata") or {}
        got = (metadata.get("ip_mode"), sorted(metadata.get("expanded_ips") or []))
        if got != (True, TARGETS):
            wrong[name] = got

    cfg = _prepared("Naabu")
    roots, groups, settings = cfg["domains"], cfg["domain_groups"], cfg["_settings"]
    for name in ("_build_recon_data_from_graph", "_build_port_scan_data_from_graph",
                 "_build_http_probe_data_from_graph", "_build_vuln_scan_data_from_graph"):
        check(name, getattr(gb, name)(roots, "u1", PID, include_root_domain=False,
                                      domain_groups=groups))
    for name in ("_build_graphql_data_from_graph", "_build_serialized_data_from_graph",
                 "_build_route_exposure_data_from_graph"):
        check(name, getattr(gb, name)(roots, "u1", PID, settings=dict(settings),
                                      domain_groups=groups))

    # The real module needs supply_chain_common, mounted only in the scan
    # container; the capture point (run_js_recon) comes before it is called.
    stub = types.ModuleType("recon.main_recon_modules.supply_chain_recon")
    stub.run_supply_chain_recon = lambda combined, *_a, **_k: combined
    monkeypatch.setitem(sys.modules, "recon.main_recon_modules.supply_chain_recon", stub)

    # Tool runners between a module and its graph writer: they would start a
    # container or a binary.
    import recon.helpers.resource_enum as resource_enum
    import recon.helpers.resource_enum.arjun_helpers as arjun_helpers
    monkeypatch.setattr(resource_enum, "run_jsluice_analysis",
                        lambda *_a, **_k: {"urls": [], "secrets": [], "external_domains": []})
    monkeypatch.setattr(arjun_helpers, "arjun_binary_check", lambda *_a, **_k: True)
    monkeypatch.setattr(arjun_helpers, "run_arjun_discovery", lambda *_a, **_k: ([], {}))

    for tool_id, (module, attr, arg, config) in SELF_BUILT.items():
        seen = _capture(monkeypatch, module, attr, arg) if module else {}
        _Client.writes = []
        try:
            _dispatch(tool_id, _prepared(tool_id, settings=SWEEP_SETTINGS, **config))
        except (_Captured, SystemExit):
            pass
        if module is None and _writer_input(attr) is not None:
            seen["data"] = _writer_input(attr)
        if "data" not in seen:
            wrong[tool_id] = f"never reached {attr}"
        else:
            check(tool_id, seen["data"])

    assert wrong == {}, json.dumps(wrong, indent=1, sort_keys=True)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-19/B-23: partial Gau and ParamSpider search the archives for ip-targets.<pid> and write a recon dict without metadata.ip_mode")
def test_partial_archive_tools_never_receive_placeholder_root(graph, monkeypatch):
    """Gau and ParamSpider build their recon dict only after the archive search,
    for the graph writer. In IP mode the synthetic root must never be searched
    (it is the project id); a run that still writes must carry the IP-mode
    metadata. Skipping both is a valid outcome."""
    import recon.helpers.resource_enum as resource_enum
    import recon.helpers.resource_enum.paramspider_helpers as paramspider_helpers
    archive_url = f"https://{PTR_NAME}/page?id=1"
    searched = {}

    def gau(domains, *_a, **_k):
        searched["Gau"] = sorted(domains)
        return [archive_url], {}

    def paramspider(domains, *_a, **_k):
        searched["ParamSpider"] = sorted(domains)
        return [archive_url], {}

    monkeypatch.setattr(resource_enum, "pull_gau_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(resource_enum, "run_gau_discovery", gau)
    monkeypatch.setattr(paramspider_helpers, "run_paramspider_discovery", paramspider)
    wrong = {}
    for tool_id in ("Gau", "ParamSpider"):
        _Client.writes = []
        try:
            _dispatch(tool_id, _prepared(tool_id, settings=SWEEP_SETTINGS))
        except SystemExit:
            pass
        if ROOT in searched.get(tool_id, []):
            wrong[f"{tool_id} searched"] = searched[tool_id]
        written = _writer_input("update_graph_from_resource_enum")
        if written is not None:
            metadata = written.get("metadata") or {}
            got = (metadata.get("ip_mode"), sorted(metadata.get("expanded_ips") or []))
            if got != (True, TARGETS):
                wrong[f"{tool_id} writer metadata"] = got

    assert wrong == {}, json.dumps(wrong, indent=1, sort_keys=True)


class _HttpResp:
    status_code = 200
    ok = True
    headers = {"Content-Type": "application/json"}
    text = "{}"
    content = b"{}"
    url = ""

    def json(self):
        return {}

    def raise_for_status(self):
        pass


def _mentions_root(blob) -> bool:
    """The synthetic root, in clear or base64-encoded (FOFA and ZoomEye queries)."""
    text = json.dumps(blob, default=str)
    if "ip-targets." in text:
        return True
    for value in (blob.get("params") or {}).values() if isinstance(blob.get("params"), dict) else []:
        try:
            decoded = base64.b64decode(str(value) + "=" * (-len(str(value)) % 4)).decode("utf-8", "ignore")
        except Exception:  # noqa: BLE001 - not base64
            continue
        if "ip-targets." in decoded:
            return True
    return False


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-19: partial OSINT/urlscan lookups send the synthetic root ip-targets.<pid> (the project id) to third parties")
def test_partial_third_party_calls_never_receive_placeholder_root(graph, monkeypatch, doc_ranges_public):
    import requests
    sent = []

    def request(self, method, url, *a, **kwargs):
        sent.append({"method": method, "url": url, "params": kwargs.get("params"),
                     "data": kwargs.get("data"), "json": kwargs.get("json")})
        return _HttpResp()

    monkeypatch.setattr(requests.sessions.Session, "request", request)
    monkeypatch.setattr("time.sleep", lambda *_a, **_k: None)
    key = "synthetic-key-0000"
    osint = dict(SETTINGS, OSINT_ENRICHMENT_ENABLED=True,
                 SHODAN_ENABLED=True, SHODAN_API_KEY=key, SHODAN_HOST_LOOKUP=True,
                 SHODAN_REVERSE_DNS=True, SHODAN_DOMAIN_DNS=True, SHODAN_PASSIVE_CVES=False,
                 URLSCAN_ENABLED=True, URLSCAN_API_KEY=key,
                 CENSYS_ENABLED=True, CENSYS_API_TOKEN=key, CENSYS_ORG_ID="org-0000",
                 FOFA_ENABLED=True, FOFA_API_KEY=key, OTX_ENABLED=True, OTX_API_KEY=key,
                 NETLAS_ENABLED=True, NETLAS_API_KEY=key, VIRUSTOTAL_ENABLED=True,
                 VIRUSTOTAL_API_KEY=key, ZOOMEYE_ENABLED=True, ZOOMEYE_API_KEY=key,
                 CRIMINALIP_ENABLED=True, CRIMINALIP_API_KEY=key)
    import recon.partial_recon as pr
    for tool_id in ("Shodan", "Urlscan", "OsintEnrichment"):
        cfg = {"tool_id": tool_id, "domains": [ROOT], "include_graph_targets": True}
        pr._prepare_scope(cfg, dict(osint), PID)
        try:
            _dispatch(tool_id, cfg)
        except SystemExit:
            pass

    assert sent, "no third-party call was made: the test exercised nothing"
    leaked = sorted({f"{r['method']} {r['url']}" for r in sent if _mentions_root(r)})
    assert leaked == [], json.dumps(leaked, indent=1)


def test_partial_dns_only_security_checks_skip_placeholder_root_already_fixed(graph, monkeypatch):
    """B-19's DNS-only sub-item is already fixed on master and this pins it.

    security_checks._dns_check_domains skips the synthetic root by its shape
    (_SYNTHETIC_IP_ROOT), so SPF/DMARC/DNSSEC/zone transfer never look up
    ip-targets.<pid> although partial recon sets no metadata.ip_mode. A plain
    test, not an xfail: it must stay green through the IP-mode fixes.
    """
    from recon.helpers import security_checks as sc
    from recon.partial_recon_modules import graph_builders as gb
    cfg = _prepared("SecurityChecks")
    recon_data = gb._build_vuln_scan_data_from_graph(cfg["domains"], "u1", PID,
                                                     domain_groups=cfg["domain_groups"])
    dns_checked = []
    monkeypatch.setattr(sc, "run_dns_checks",
                        lambda domain, **_k: dns_checked.append(domain) or [])
    sc.run_security_checks(recon_data, {c: True for c in (
        "spf_missing", "dmarc_missing", "dnssec_missing", "zone_transfer")}, timeout=1)

    assert dns_checked == []


# ---------------------------------------------------------------------------
# B-20 / B-22: typed inputs
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-20/B-22: typed IPs are never checked against the targets, URL hosts not CIDR-aware, ip_attach_to unchecked")
def test_partial_typed_ip_outside_targets_refused(graph):
    cfg = _prepared("Naabu", user_targets={
        "ips": ["203.0.113.1", FOREIGN, "198.51.100.0/30", TYPED],
        "urls": ["http://203.0.113.2:8080/", f"http://{FOREIGN}/", f"http://{TYPED}/"],
        "ip_attach_to": PTR_NAME,
    })
    targets = cfg["user_targets"]

    assert targets["ips"] == ["203.0.113.1", TYPED]
    # 203.0.113.2 is inside the target CIDR 203.0.113.0/30.
    assert targets["urls"] == ["http://203.0.113.2:8080/", f"http://{TYPED}/"]
    # Only a target's placeholder may take typed IPs: a PTR name's RESOLVES_TO
    # edge is read back as forward DNS by every later partial run.
    assert targets["ip_attach_to"] is None


# ---------------------------------------------------------------------------
# B-21: PTR names, their forward addresses and placeholders as partial targets
# ---------------------------------------------------------------------------

@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-21: the partial graph builders read a PTR name's forward address as a target")
def test_partial_graph_builder_drops_ptr_forward_ip(graph):
    from recon.partial_recon_modules import graph_builders as gb
    cfg = _prepared("Naabu")
    leaks = {}
    for name in ("_build_recon_data_from_graph", "_build_port_scan_data_from_graph",
                 "_build_http_probe_data_from_graph", "_build_vuln_scan_data_from_graph"):
        data = getattr(gb, name)(cfg["domains"], "u1", PID, include_root_domain=False,
                                 domain_groups=cfg["domain_groups"])
        bad = _outside(_recon_ips(data))
        if bad:
            leaks[name] = bad
    assert leaks == {}, leaks


def _crawl_seeds(monkeypatch, tool_id: str, runner: str) -> list:
    import recon.helpers.resource_enum as resource_enum
    seen = {}

    def run(seeds, *_a, **_k):
        seen["seeds"] = list(seeds)
        raise _Captured

    monkeypatch.setattr(resource_enum, runner, run)
    for name in ("pull_katana_docker_image", "pull_zap_ajax_docker_image"):
        monkeypatch.setattr(resource_enum, name, lambda *_a, **_k: True)
    with pytest.raises(_Captured):
        _dispatch(tool_id, _prepared(tool_id))
    return seen["seeds"]


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-21: graph_url_scope keeps hosts under no Domain and build_target_urls source 3 adds the PTR name")
def test_partial_crawler_urls_have_no_ptr_name_or_placeholder(graph, monkeypatch):
    seeds = {"Katana": _crawl_seeds(monkeypatch, "Katana", "run_katana_crawler"),
             "ZapAjaxSpider": _crawl_seeds(monkeypatch, "ZapAjaxSpider", "run_zap_ajax_spider")}

    off_target = {tool: _outside(map(_host, urls)) for tool, urls in seeds.items()}
    assert off_target == {"Katana": [], "ZapAjaxSpider": []}
    assert all("http://203.0.113.2" in urls for urls in seeds.values())


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-21: partial httpx probes the placeholder and the PTR name as hostnames")
def test_partial_httpx_probes_ip_literal_not_placeholder(graph, monkeypatch):
    from recon.main_recon_modules import http_probe
    seen = {}

    def build(targets_file, *_a, **_k):
        seen["urls"] = Path(targets_file).read_text().split()
        raise _Captured

    monkeypatch.setattr(http_probe, "build_httpx_command", build)
    monkeypatch.setattr(http_probe, "is_docker_installed", lambda: True)
    monkeypatch.setattr(http_probe, "is_docker_running", lambda: True)
    monkeypatch.setattr(http_probe, "pull_httpx_docker_image", lambda *_a, **_k: True)
    with pytest.raises(_Captured):
        _dispatch("Httpx", _prepared("Httpx"))

    assert _outside(map(_host, seen["urls"])) == []
    assert "http://203.0.113.2" in seen["urls"]


# ---------------------------------------------------------------------------
# B-19 / B-08 / D-11: the name-only tools are refused in IP mode
# ---------------------------------------------------------------------------

# The reason the run report gives a root refused because the project is in IP
# mode. Chosen here for P0c to implement: print_run_report prints
# "<root>: refused: IP mode ..." (any detail may follow the token).
IP_MODE_REFUSAL = "refused: IP mode"


def _run_main(monkeypatch, capsys, tool_id: str):
    """partial_recon.main() for one tool in IP mode: (exit code, report reason of the root)."""
    import recon.partial_recon as pr
    monkeypatch.setattr("recon.graph_db_preflight.require_graph_db", lambda *_a: None)
    monkeypatch.setattr(pr, "get_settings", lambda: dict(SETTINGS))
    monkeypatch.setattr(pr, "_cleanup_orphan_user_inputs", lambda *_a: 0)
    monkeypatch.setattr(pr, "_apply_node_filters", lambda *_a: None)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump({"tool_id": tool_id, "domains": [ROOT]}, f)
    monkeypatch.setenv("PARTIAL_RECON_CONFIG", f.name)
    try:
        pr.main()
        code = 0
    except SystemExit as e:
        code = e.code
    finally:
        os.unlink(f.name)
    out = capsys.readouterr().out
    report = out[out.index(f"Run report: {tool_id}"):] if f"Run report: {tool_id}" in out else ""
    prefix = f"[*][Partial Recon]   {ROOT}: "
    reason = next((line[len(prefix):] for line in report.splitlines() if line.startswith(prefix)), None)
    return code, reason


def _assert_refused(code, reason, scanner_calls):
    """Refused before the scanner: exit 1, and the root's report reason is the
    IP-mode refusal (today a run that ran and found nothing says no_results)."""
    refused = bool(reason) and reason.startswith(IP_MODE_REFUSAL) and "no_results" not in reason
    got = {"exit code": code, "reason is the IP-mode refusal": refused, "scanner calls": scanner_calls}
    assert got == {"exit code": 1, "reason is the IP-mode refusal": True, "scanner calls": []}, (
        f"report reason for {ROOT}: {reason!r}")


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-19: partial SubdomainDiscovery enumerates ip-targets.<pid> in IP mode")
def test_partial_subdomain_discovery_refused_in_ip_mode(graph, monkeypatch, capsys):
    from recon.main_recon_modules import domain_recon
    enumerated = []
    monkeypatch.setattr(domain_recon, "discover_subdomains", lambda domain, **_k: enumerated.append(domain) or {
        "subdomains": [], "subdomain_count": 0, "dns": {}})

    code, reason = _run_main(monkeypatch, capsys, "SubdomainDiscovery")

    _assert_refused(code, reason, enumerated)


@pytest.mark.xfail(strict=True, raises=AssertionError, reason="B-19/D-11, B-08: partial Urlscan searches ip-targets.<pid> and OriginDiscovery probes non-target origins in IP mode")
@pytest.mark.parametrize("tool_id, module, scanner", [
    ("Urlscan", "recon.main_recon_modules.urlscan_enrich", "run_urlscan_discovery_only"),
    ("OriginDiscovery", "recon.main_recon_modules.origin_discovery", "run_origin_discovery_enrichment"),
])
def test_partial_urlscan_and_origin_discovery_refused_in_ip_mode(graph, monkeypatch, capsys,
                                                                 tool_id, module, scanner):
    import importlib
    called = []

    def record(target, *_a, **_k):
        called.append(target.get("domain") if isinstance(target, dict) else target)
        return {}

    monkeypatch.setattr(importlib.import_module(module), scanner, record)

    code, reason = _run_main(monkeypatch, capsys, tool_id)

    _assert_refused(code, reason, called)
