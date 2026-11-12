"""IP-mode partial recon keeps to the target list (P0c: B-19 .. B-23, S-6).

The rule pieces one by one, beside the end-to-end characterisation tests in
test_regression_partial_ip_mode_leaks.py: the run's expanded target list, the
typed-input filter (CIDR-aware, any IPv6 spelling), the attach rule for typed
IPs, the refused name-only tools, the graph readers (Subdomain -> IP rows, the
BaseURL scope, the archive hosts) and the modules' last clamps. Neo4j, DNS and
the tools are fakes.

A real name is a target only when it is one of the run's hostnames
(S, computed once at the run's start: test_partial_ip_hostnames.py), and the
graph readers still drop one whose graph addresses leave the targets. The
tests that keep a name put it in S first (the ``ip_names`` fixture).

Documentation addresses (RFC 5737, RFC 3849) and reserved names only.
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.partial_recon_modules import graph_builders as gb  # noqa: E402
from recon.partial_recon_modules import helpers  # noqa: E402

PID = "cmipmodescope000000000001"
ROOT = f"ip-targets.{PID}"
TARGET_IPS = ["203.0.113.0/30", "203.0.113.9", "2001:db8::1"]
SETTINGS = {"IP_MODE": True, "TARGET_IPS": list(TARGET_IPS), "ROE_ENABLED": False,
            "ROE_EXCLUDED_HOSTS": [], "DOMAIN_BATCH_MODE": False, "TARGET_DOMAIN": ""}
LABEL, LABEL_V6 = "203-0-113-2", "2001-db8--1"
GOOD_NAME = "www.example.com"      # every address a target
SPLIT_NAME = "mail.example.com"     # one address a target, one not
FOREIGN_NAME = "ftp.example.com"    # no address a target
FOREIGN = "198.51.100.7"

# (subdomain, address) forward-DNS rows under the synthetic root
ROWS = [
    (LABEL, "203.0.113.2"),
    (LABEL, FOREIGN),                  # an attach to a foreign address (B-20)
    (LABEL_V6, "2001:db8::1"),
    (GOOD_NAME, "203.0.113.1"),
    (GOOD_NAME, "203.0.113.9"),
    (SPLIT_NAME, "203.0.113.1"),
    (SPLIT_NAME, FOREIGN),
    (FOREIGN_NAME, FOREIGN),
]


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    helpers.set_run_ip_targets({})
    helpers.set_run_roe({})
    yield
    helpers.set_run_ip_targets({})
    helpers.set_run_roe({})
    circuit_breaker.reset_registry()


@pytest.fixture
def ip_run():
    helpers.set_run_ip_targets(SETTINGS)


@pytest.fixture
def ip_names(ip_run):
    """Every name of ROWS in S: each is then judged on its graph rows alone."""
    helpers.set_run_ip_hostnames({GOOD_NAME: "example.com", SPLIT_NAME: "example.com",
                                  FOREIGN_NAME: "example.com"})


def _only_good_name():
    helpers.set_run_ip_hostnames({GOOD_NAME: "example.com"})


class _Result(list):
    def single(self):
        return self[0] if self else None


class _Session:
    def __init__(self, log, rows=ROWS, baseurls=()):
        self.log, self.rows, self.baseurls = log, rows, baseurls

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        self.log.append(cypher)
        out = _Result()
        if "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            if ROOT in [str(d).lower() for d in params.get("domains") or []]:
                for sub, ip in self.rows:
                    out.append({"root": ROOT, "subdomain": sub, "address": ip, "ip": ip, "version": None,
                                "ports": [{"number": 80, "protocol": "tcp", "passive_only": None}],
                                "is_cdn": None, "cdn_name": None, "asn": None})
        elif "collect(DISTINCT s.name)" in cypher:
            out.append({"subdomains": sorted({s for s, _ in self.rows})})
        elif "MATCH (b:BaseURL" in cypher and "AS status_code" in cypher:
            for url, host in self.baseurls:
                out.append({"url": url, "host": host, "status_code": 200, "content_type": "text/html"})
        return out


class _Client:
    reachable = True
    log: list = []
    rows = ROWS
    baseurls: tuple = ()

    def __init__(self, *_a, **_k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return _Client.reachable

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda **_k: _Session(_Client.log, _Client.rows, _Client.baseurls)
        return driver


@pytest.fixture
def graph(monkeypatch):
    _Client.reachable, _Client.log, _Client.rows, _Client.baseurls = True, [], ROWS, ()
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr("graph_db.neo4j_client.Neo4jClient", _Client)
    return _Client


# ---------------------------------------------------------------------------
# The run's target list and the stamp
# ---------------------------------------------------------------------------

def test_the_run_list_is_set_from_the_settings_and_cleared_outside_ip_mode():
    helpers.set_run_ip_targets(SETTINGS)
    assert helpers.run_ip_targets() == ["203.0.113.1", "203.0.113.2", "203.0.113.9", "2001:db8::1"]
    helpers.set_run_ip_targets({"IP_MODE": False, "TARGET_IPS": ["203.0.113.9"]})
    assert helpers.run_ip_targets() is None


def test_prepare_scope_sets_the_list_before_the_typed_input_filter():
    import recon.partial_recon as pr
    cfg = {"tool_id": "Naabu", "domains": [ROOT],
           "user_targets": {"ips": ["203.0.113.9"], "ip_attach_to": LABEL}}
    pr._prepare_scope(cfg, dict(SETTINGS), PID)
    assert helpers.run_ip_targets()[-1] == "2001:db8::1"
    assert cfg["user_targets"]["ip_attach_to"] == LABEL
    pr._prepare_scope({"tool_id": "Naabu", "domains": ["example.com"]},
                      {"IP_MODE": False, "TARGET_DOMAIN": "example.com", "SUBDOMAIN_LIST": ["."]}, PID)
    assert helpers.run_ip_targets() is None


def test_a_target_label_stands_for_its_own_address_only():
    expanded = helpers.ip_mode_target_list(SETTINGS)
    assert helpers.is_target_label(LABEL, expanded)
    assert helpers.is_target_label(LABEL_V6, expanded)
    for name in ("203-0-113-3", "198-51-100-7", GOOD_NAME, f"{LABEL}.{ROOT}", None, 7):
        assert not helpers.is_target_label(name, expanded), name


# ---------------------------------------------------------------------------
# Typed input (container side; the orchestrator copy runs the same cases)
# ---------------------------------------------------------------------------

def _filter(user_targets, settings=None, **config):
    cfg = {"domain_groups": [], "user_targets": user_targets, **config}
    refused = helpers.filter_partial_user_input(cfg, dict(settings or SETTINGS))
    return cfg, refused


def test_a_typed_cidr_inside_the_targets_is_kept_as_typed():
    cfg, refused = _filter({"ips": ["203.0.113.0/30", "203.0.113.9/32", "2001:db8::1/128"]})
    assert cfg["user_targets"]["ips"] == ["203.0.113.0/30", "203.0.113.9/32", "2001:db8::1/128"]
    assert refused == []


def test_a_typed_cidr_across_the_targets_keeps_its_target_hosts_only():
    cfg, refused = _filter({"ips": ["203.0.113.0/29", "198.51.100.0/30"]})
    assert cfg["user_targets"]["ips"] == ["203.0.113.1", "203.0.113.2"]
    assert refused == [
        "ip 203.0.113.3, 203.0.113.4, 203.0.113.5, 203.0.113.6 in '203.0.113.0/29' "
        "(not one of the project's target IPs)",
        "ip 198.51.100.1, 198.51.100.2 in '198.51.100.0/30' (not one of the project's target IPs)",
    ]


def test_a_typed_address_matches_in_any_ipv6_spelling_and_never_by_routability():
    cfg, refused = _filter({"ips": ["2001:DB8:0:0:0:0:0:1", "203.0.113.0", "203.0.113.3", "10.0.0.1"],
                            "urls": ["http://[2001:db8::1]:8443/", "http://203.0.113.3/"]})
    assert cfg["user_targets"]["ips"] == ["2001:DB8:0:0:0:0:0:1"]
    assert cfg["user_targets"]["urls"] == ["http://[2001:db8::1]:8443/"]
    assert len(refused) == 4


def test_a_typed_name_is_never_an_ip_mode_target():
    cfg, refused = _filter({"subdomains": [GOOD_NAME], "urls": [f"http://{GOOD_NAME}/"]},
                           user_inputs=[GOOD_NAME, "203.0.113.9"])
    assert cfg["user_targets"]["subdomains"] == [] and cfg["user_targets"]["urls"] == []
    assert cfg["user_inputs"] == ["203.0.113.9"]
    assert len(refused) == 3


def test_an_excluded_target_is_refused_by_the_roe_not_as_an_outsider():
    settings = dict(SETTINGS, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["203.0.113.2"])
    cfg, refused = _filter({"ips": ["203.0.113.2", "203.0.113.0/30"]}, settings)
    assert cfg["user_targets"]["ips"] == ["203.0.113.1"]
    assert all("Rules of Engagement" in r for r in refused) and len(refused) == 2


def test_typed_ips_attach_only_to_a_targets_own_label():
    cfg, refused = _filter({"ips": ["203.0.113.9"], "ip_attach_to": LABEL})
    assert cfg["user_targets"]["ip_attach_to"] == LABEL and refused == []
    for name in (GOOD_NAME, "198-51-100-7", f"{LABEL}.{ROOT}"):
        cfg, refused = _filter({"ips": ["203.0.113.9"], "ip_attach_to": name})
        assert cfg["user_targets"]["ip_attach_to"] is None
        assert refused == [f"ip_attach_to {name!r} (not a target's own label)"]


def test_domain_mode_typed_input_is_unchanged():
    domain = {"IP_MODE": False, "ROE_ENABLED": False}
    groups = [{"scanRoot": "example.com", "orgDomain": "example.com", "mode": "enumerate",
               "includeRoot": True, "exactHosts": [], "rootDomain": "example.com", "prefixes": ["*", "."],
               "batch": False}]
    cfg, refused = _filter({"ips": ["198.51.100.0/30", "198.51.100.7"], "ip_attach_to": GOOD_NAME},
                           domain, domain_groups=groups)
    assert cfg["user_targets"] == {"ips": ["198.51.100.0/30", "198.51.100.7"], "ip_attach_to": GOOD_NAME}
    assert refused == []


def test_the_modules_attach_typed_ips_to_a_label_only(ip_run, capsys):
    assert helpers.typed_ip_attach_to({"ip_attach_to": LABEL}) == LABEL
    assert helpers.typed_ip_attach_to({"ip_attach_to": GOOD_NAME}) is None
    assert "only a target's own label" in capsys.readouterr().out
    assert helpers.typed_ip_attach_to({}) is None
    helpers.set_run_ip_targets({})
    assert helpers.typed_ip_attach_to({"ip_attach_to": GOOD_NAME}) == GOOD_NAME


# ---------------------------------------------------------------------------
# The refused name-only tools
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool_id, runner", [
    ("SubdomainDiscovery", "run_subdomain_discovery"),
    ("Urlscan", "run_urlscan"),
    ("OriginDiscovery", "run_origin_discovery"),
])
def test_dispatch_refuses_a_name_only_tool_in_ip_mode(monkeypatch, tool_id, runner):
    import recon.partial_recon as pr
    called = []
    monkeypatch.setattr(pr, runner, lambda *_a: called.append(tool_id))
    statuses = pr._dispatch(tool_id, {"domains": [ROOT], "ip_mode": True})
    assert called == []
    assert statuses == {ROOT: helpers.ip_mode_refusal(tool_id, SETTINGS)}
    assert statuses[ROOT].startswith(helpers.IP_MODE_REFUSAL)
    assert pr.run_exit_code(statuses) == 1
    pr._dispatch(tool_id, {"domains": ["example.com"], "ip_mode": False})
    assert called == [tool_id]


def test_only_the_name_only_tools_are_refused():
    assert {t for t in ("SubdomainDiscovery", "Urlscan", "OriginDiscovery", "Httpx", "Uncover", "Shodan")
            if helpers.ip_mode_refusal(t, SETTINGS)} == {"SubdomainDiscovery", "Urlscan", "OriginDiscovery"}
    assert helpers.ip_mode_refusal("Urlscan", {"IP_MODE": False}) is None


def test_urlscan_discovery_never_searches_an_ip_mode_root(monkeypatch):
    import requests
    from recon.main_recon_modules import urlscan_enrich
    monkeypatch.setattr(requests.sessions.Session, "request",
                        lambda *_a, **_k: pytest.fail("urlscan.io was called in IP mode"))
    assert urlscan_enrich.run_urlscan_discovery_only(
        ROOT, {"URLSCAN_ENABLED": True, "IP_MODE": True, "URLSCAN_API_KEY": "synthetic-key"}) == {}


# ---------------------------------------------------------------------------
# The graph readers
# ---------------------------------------------------------------------------

def _rows(rows=ROWS):
    return [{"subdomain": s, "address": a} for s, a in rows]


def test_rows_pass_unchanged_outside_ip_mode():
    rows = _rows()
    assert gb._ip_mode_rows(rows, "subdomain", "address") is rows


def test_rows_keep_a_labels_target_address_and_names_in_s_wholly_on_targets(ip_names, capsys):
    kept = gb._ip_mode_rows(iter(_rows()), "subdomain", "address")
    assert [(r["subdomain"], r["address"]) for r in kept] == [
        (LABEL, "203.0.113.2"), (LABEL_V6, "2001:db8::1"),
        (GOOD_NAME, "203.0.113.1"), (GOOD_NAME, "203.0.113.9")]
    assert "outside the IP target list" in capsys.readouterr().out


def test_rows_drop_a_name_wholly_on_targets_that_is_not_in_s(ip_run):
    kept = gb._ip_mode_rows(iter(_rows()), "subdomain", "address")
    assert [(r["subdomain"], r["address"]) for r in kept] == [
        (LABEL, "203.0.113.2"), (LABEL_V6, "2001:db8::1")]


def test_a_name_left_out_of_the_rows_leaves_the_flat_list_too(ip_run):
    data = {"dns": {"subdomains": {LABEL: {}, GOOD_NAME: {}}}}
    assert gb._ip_mode_kept_host(data, GOOD_NAME) and not gb._ip_mode_kept_host(data, SPLIT_NAME)
    helpers.set_run_ip_targets({})
    assert gb._ip_mode_kept_host(data, SPLIT_NAME)


def test_the_port_builder_keys_a_label_by_its_address(graph, ip_names):
    data = gb._build_port_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    ps = data["port_scan"]
    assert sorted(ps["by_host"]) == sorted(["203.0.113.2", "2001:db8::1", GOOD_NAME])
    assert ps["by_host"]["203.0.113.2"]["host"] == "203.0.113.2"
    assert ps["by_ip"]["203.0.113.2"]["hostnames"] == []
    assert ps["by_ip"]["203.0.113.9"]["hostnames"] == [GOOD_NAME]
    assert ps["ip_to_hostnames"] == {"203.0.113.1": [GOOD_NAME], "203.0.113.9": [GOOD_NAME]}
    assert sorted(ps["by_ip"]) == ["2001:db8::1", "203.0.113.1", "203.0.113.2", "203.0.113.9"]
    assert data["metadata"]["ip_mode"] is True


def test_the_port_builder_keeps_domain_rows_by_name(graph):
    data = gb._build_port_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert LABEL in data["port_scan"]["by_host"] and FOREIGN_NAME in data["port_scan"]["by_host"]
    assert "ip_mode" not in data["metadata"]


def test_the_flat_subdomain_list_drops_a_name_with_a_foreign_address(graph, ip_names):
    data = gb._build_http_probe_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["subdomains"]) == sorted([LABEL, LABEL_V6, GOOD_NAME])
    data = gb._build_vuln_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["subdomains"]) == sorted([LABEL, LABEL_V6, GOOD_NAME])


def test_the_url_scope_keeps_target_addresses_and_the_runs_names(graph, ip_run):
    _only_good_name()
    session = _Session(graph.log)
    keep = gb.graph_url_scope(session, "u1", PID, [ROOT], [])
    assert keep("203.0.113.2") and keep("[2001:db8::1]") and keep("2001:DB8::1") and keep("")
    assert not keep(FOREIGN) and not keep("203.0.113.3")
    assert keep(GOOD_NAME) and keep(GOOD_NAME.upper())
    for host in (SPLIT_NAME, FOREIGN_NAME, LABEL, "cdn.third-party.test"):
        assert not keep(host), host
    # S was judged on live DNS at the run's start: the graph's answers are not read.
    assert not any("RESOLVES_TO" in q for q in graph.log)


def test_the_url_scope_applies_the_roe_in_ip_mode(graph, ip_run):
    helpers.set_run_roe({"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["203.0.113.2", GOOD_NAME]})
    keep = gb.graph_url_scope(_Session(graph.log), "u1", PID, [ROOT], [])
    assert not keep("203.0.113.2") and not keep(GOOD_NAME) and keep("203.0.113.1")


def test_the_crawler_builder_drops_baseurls_off_the_targets(graph, ip_run):
    _only_good_name()
    graph.baseurls = (("http://203.0.113.2", "203.0.113.2"), (f"https://{GOOD_NAME}", GOOD_NAME),
                      (f"https://{SPLIT_NAME}", SPLIT_NAME), (f"http://{FOREIGN}", FOREIGN),
                      ("http://[2001:db8::1]:8080", "2001:db8::1"), (f"http://{LABEL}", LABEL))
    data = gb._build_http_probe_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["http_probe"]["by_url"]) == sorted(
        ["http://203.0.113.2", f"https://{GOOD_NAME}", "http://[2001:db8::1]:8080"])


def test_the_archive_hosts_are_the_runs_names(graph, ip_run):
    _only_good_name()
    assert gb.graph_target_hosts("u1", PID, [ROOT], []) == [GOOD_NAME]
    assert gb.graph_target_hosts("u1", PID, [ROOT], [], include_graph=False) == []
    assert gb.graph_target_hosts("u1", PID, [], []) == []
    helpers.set_run_roe({"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [GOOD_NAME]})
    assert gb.graph_target_hosts("u1", PID, [ROOT], []) == []


def test_the_archive_hosts_are_none_without_s(graph, ip_run):
    # S is empty when the graph could not be read at the run's start.
    assert gb.graph_target_hosts("u1", PID, [ROOT], []) == []
    assert graph.log == []


# ---------------------------------------------------------------------------
# The modules' last clamps
# ---------------------------------------------------------------------------

def test_gau_searches_only_the_runs_names_and_stamps_its_write(graph, monkeypatch):
    import recon.partial_recon as pr
    import recon.helpers.resource_enum as resource_enum
    searched, written = [], []
    monkeypatch.setattr(resource_enum, "pull_gau_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(resource_enum, "run_gau_discovery",
                        lambda domains, *_a, **_k: searched.append(sorted(domains)) or (
                            [f"https://{GOOD_NAME}/page?id=1"], {}))
    monkeypatch.setattr(_Client, "update_graph_from_resource_enum",
                        lambda self, recon_data, **_k: written.append(recon_data) or {}, raising=False)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    cfg = {"tool_id": "Gau", "domains": [ROOT], "include_graph_targets": True}
    pr._prepare_scope(cfg, dict(SETTINGS, GAU_VERIFY_URLS=False, GAU_DETECT_METHODS=False,
                                IP_HOSTNAME_MODE="record_filter"), PID)
    _only_good_name()      # what the run's start selected (the fake graph records no name)
    pr._dispatch("Gau", cfg)
    assert searched == [[GOOD_NAME]]
    assert written and written[0]["metadata"]["ip_mode"] is True
    assert written[0]["metadata"]["expanded_ips"] == helpers.run_ip_targets()


def test_paramspider_skips_an_ip_mode_run_with_no_name_on_the_targets(graph, monkeypatch, capsys):
    import recon.partial_recon as pr
    import recon.helpers.resource_enum.paramspider_helpers as paramspider_helpers
    graph.rows = [(LABEL, "203.0.113.2"), (FOREIGN_NAME, FOREIGN)]
    monkeypatch.setattr(paramspider_helpers, "run_paramspider_discovery",
                        lambda *_a, **_k: pytest.fail("the archive was searched"))
    cfg = {"tool_id": "ParamSpider", "domains": [ROOT], "include_graph_targets": True}
    # ip_only and record_only refuse ParamSpider outright (test_partial_ip_hostnames.py).
    pr._prepare_scope(cfg, dict(SETTINGS, IP_HOSTNAME_MODE="record_filter"), PID)
    pr._dispatch("ParamSpider", cfg)
    assert "[-][ParamSpider] IP mode: no hostname" in capsys.readouterr().out


def test_ai_surface_reads_vector_db_ports_on_targets_only(monkeypatch):
    from recon.partial_recon_modules import ai_surface_recon as partial_ai

    class _AiSession(_Session):
        def run(self, cypher, **params):
            if "ip.address AS ip" in cypher:
                return _Result([{"ip": "203.0.113.2"}, {"ip": FOREIGN}])
            if "ai_interface_type" in cypher:
                return _Result([{"base_url": "http://203.0.113.2", "path": "/v1/chat", "method": "POST",
                                 "iface": "openai-compatible", "ai_fw": False, "declared_only": False}])
            return _Result()

    asked = []

    class _AiClient:
        def __init__(self, *_a, **_k):
            self.driver = mock.MagicMock()
            self.driver.session.side_effect = lambda **_k: _AiSession([])

        def active_open_ports(self, _uid, _pid, ips):
            asked.append(sorted(ips))
            return {}

        def update_graph_from_ai_surface_recon(self, *_a, **_k):
            return {}

        def close(self):
            pass

    monkeypatch.setattr("graph_db.neo4j_client.Neo4jClient", _AiClient)
    monkeypatch.setattr("recon.main_recon_modules.ai_surface_recon.run_ai_surface_recon",
                        lambda recon_data, **_k: recon_data)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    # No run list here: the stamp from the settings is what the clamp reads.
    partial_ai.run_ai_surface_recon({"domains": [ROOT], "domain_groups": [], "_settings": dict(SETTINGS)})
    assert asked == [["203.0.113.2"]]


def test_the_ip_attribution_placeholder_check_is_the_shared_one():
    from recon.helpers.ip_placeholders import is_placeholder
    from recon.partial_recon_modules import ip_attribution
    assert ip_attribution._is_placeholder is is_placeholder
    data = {"dns": {"subdomains": {LABEL: {}, GOOD_NAME: {}, "1-2-3": {}}}}
    ip_attribution._mark_placeholders(data)
    assert data["dns"]["subdomains"] == {LABEL: {"is_mock": True}, GOOD_NAME: {}, "1-2-3": {}}


def test_the_name_rule_answers_nothing_outside_ip_mode():
    assert gb._ip_mode_names({GOOD_NAME: ["203.0.113.1"]}) == (None, None)


def test_a_label_on_an_address_a_name_already_holds_adds_no_hostname(graph, ip_names):
    graph.rows = [(GOOD_NAME, "203.0.113.1"), ("203-0-113-1", "203.0.113.1")]
    ps = gb._build_port_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])["port_scan"]
    assert ps["by_ip"]["203.0.113.1"]["hostnames"] == [GOOD_NAME]
    assert sorted(ps["by_host"]) == ["203.0.113.1", GOOD_NAME]
