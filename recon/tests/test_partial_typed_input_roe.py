"""A partial run's typed input against the RoE exclusion list (R-6, typed half).

The graph builders drop RoE-excluded hosts and IPs (30cf1a57); what the
operator types reached the tools with a scope check only, so a host the client
excluded after a full scan was still probed when typed into the partial modal,
and a typed IP or CIDR was checked for width alone. filter_partial_user_input
now drops an excluded host, URL, IP or attach target, keeps the other hosts of
a typed CIDR that holds an excluded address, names the Rules of Engagement in
each refusal and records one `roe_excluded` coverage note.

Under RoE IP or CIDR entries a typed name (a subdomain, a URL host, the name
typed IPs attach to) passes only when every address it resolves to is admitted
(D2): the tools are handed the name and resolve it themselves, so a name with
one address in an excluded range, or with no address at all, is refused.

The table in fixtures/partial_typed_input_roe_vectors.json is also run against
the orchestrator's copy (recon_orchestrator/tests/test_partial_typed_input_roe.py),
which filters the same payload before the container starts. DNS is a fake
socket.getaddrinfo serving each vector's 'resolved' map.
Reserved names and documentation ranges only.
"""
import json
import os
import socket
import sys
import tempfile
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.partial_recon_modules.helpers import (  # noqa: E402
    filter_partial_user_input,
    partial_domain_groups,
)
from recon.project_settings import DEFAULT_SETTINGS  # noqa: E402

VECTORS_PATH = Path(__file__).resolve().parent / "fixtures" / "partial_typed_input_roe_vectors.json"
VECTORS = json.loads(VECTORS_PATH.read_text())["vectors"]

GROUP = {"scanRoot": "example.com", "orgDomain": "example.com", "mode": "enumerate",
         "includeRoot": True, "exactHosts": []}
TARGET_IPS = ["192.0.2.10", "192.0.2.11"]
RoE = "Rules of Engagement"


def _settings(excluded, ip_mode=False):
    base = {"IP_MODE": ip_mode, "DOMAIN_BATCH_MODE": False,
            "ROE_ENABLED": bool(excluded), "ROE_EXCLUDED_HOSTS": list(excluded)}
    if ip_mode:
        return dict(base, TARGET_IPS=TARGET_IPS)
    return dict(base, TARGET_DOMAIN="example.com", SUBDOMAIN_LIST=["."], SCOPE_GROUPS=[GROUP])


def _config(settings, typed):
    targets = {k: v for k, v in typed.items() if k != "user_inputs"}
    roots = ["ip-targets.p1"] if settings["IP_MODE"] else ["example.com"]
    return {"domain_groups": partial_domain_groups(settings, roots),
            "user_inputs": list(typed.get("user_inputs", [])), "user_targets": targets}


@pytest.fixture(autouse=True)
def _fresh_notes():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


class FakeDns:
    """socket.getaddrinfo over a {name: [addresses]} table; a name it does not
    list has no address. Records every name asked."""

    def __init__(self, table=None):
        self.table = dict(table or {})
        self.asked = []

    def __call__(self, host, port=None, *args, **kwargs):
        self.asked.append(host)
        answers = self.table.get(str(host).rstrip(".").lower())
        if not answers:
            raise socket.gaierror(socket.EAI_NONAME, "Name or service not known")
        return [(socket.AF_INET6 if ":" in a else socket.AF_INET, socket.SOCK_STREAM, 6, "",
                 (a, 0, 0, 0) if ":" in a else (a, 0)) for a in answers]


@pytest.fixture(autouse=True)
def dns(monkeypatch):
    """No test here reaches a real resolver."""
    fake = FakeDns()
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    return fake


def test_the_table_is_real():
    assert len(VECTORS) >= 15
    assert sum(v["roe_refused"] for v in VECTORS) >= 15
    assert sum("resolved" in v and not v.get("no_lookup") for v in VECTORS) >= 7


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(v, dns):
    dns.table = dict(v.get("resolved") or {})
    settings = _settings(v["excluded"], v.get("ip_mode", False))
    config = _config(settings, v["typed"])
    refused = filter_partial_user_input(config, settings)
    got = dict(config["user_targets"], user_inputs=config["user_inputs"])
    for key, expected in v["kept"].items():
        assert got.get(key) == expected, key
    assert sum(RoE in r for r in refused) == v["roe_refused"], refused
    if v.get("no_lookup"):
        assert dns.asked == []


class TestTheRefusalIsRecorded:
    def _roe_gaps(self):
        return [g for g in circuit_breaker.coverage_report().gaps
                if g.get("source") == "roe_excluded"]

    def test_one_coverage_note_counts_every_excluded_input(self, dns):
        dns.table = {"www.example.com": ["192.0.2.7"]}
        settings = _settings(["legacy.example.com", "192.0.2.2"])
        config = _config(settings, {"subdomains": ["legacy.example.com", "www.example.com"],
                                    "urls": ["https://legacy.example.com/a"],
                                    "ips": ["192.0.2.0/29"]})
        refused = filter_partial_user_input(config, settings)
        assert sum(RoE in r for r in refused) == 3
        gaps = self._roe_gaps()
        assert len(gaps) == 1
        assert gaps[0]["skipped"] == 3

    def test_no_note_when_nothing_is_excluded(self):
        settings = _settings(["legacy.example.com"])
        config = _config(settings, {"subdomains": ["www.example.com"], "ips": ["192.0.2.1"]})
        assert filter_partial_user_input(config, settings) == []
        assert self._roe_gaps() == []

    def test_an_unresolved_name_is_noted_as_such(self, dns):
        dns.table = {"legacy.example.com": ["198.51.100.20"]}
        settings = _settings(["198.51.100.0/24"])
        config = _config(settings, {"subdomains": ["legacy.example.com", "ghost.example.com"]})
        filter_partial_user_input(config, settings)
        gaps = self._roe_gaps()
        # The coverage record keeps one gap per source, with each reason.
        assert len(gaps) == 1 and gaps[0]["skipped"] == 2
        assert "excluded by the Rules of Engagement" in gaps[0]["reason"]
        assert "no address" in gaps[0]["reason"]

    def test_a_switched_off_rule_set_excludes_nothing(self):
        settings = dict(_settings(["legacy.example.com"]), ROE_ENABLED=False)
        config = _config(settings, {"subdomains": ["legacy.example.com"]})
        assert filter_partial_user_input(config, settings) == []
        assert config["user_targets"]["subdomains"] == ["legacy.example.com"]


class TestAddressRefusals:
    EXCLUDED = ["198.51.100.0/24"]

    def _run(self, typed, table, dns, excluded=None):
        dns.table = table
        settings = _settings(excluded or self.EXCLUDED)
        config = _config(settings, typed)
        return config, filter_partial_user_input(config, settings)

    def test_the_refusal_names_the_excluded_address(self, dns):
        _, refused = self._run({"subdomains": ["legacy.example.com"]},
                               {"legacy.example.com": ["198.51.100.20"]}, dns)
        assert len(refused) == 1
        assert "'legacy.example.com'" in refused[0] and "198.51.100.20" in refused[0]
        assert RoE in refused[0]

    def test_a_mixed_name_names_only_its_excluded_address(self, dns):
        _, refused = self._run({"urls": ["https://mixed.example.com/x"]},
                               {"mixed.example.com": ["192.0.2.8", "198.51.100.21"]}, dns)
        assert len(refused) == 1
        assert "198.51.100.21" in refused[0] and "192.0.2.8" not in refused[0]

    def test_a_name_with_no_address_says_so(self, dns):
        _, refused = self._run({"subdomains": ["ghost.example.com"]}, {}, dns)
        assert len(refused) == 1 and "no address" in refused[0] and RoE in refused[0]

    def test_a_name_is_resolved_once_whatever_lists_carry_it(self, dns):
        config, refused = self._run(
            {"user_inputs": ["www.example.com"], "subdomains": ["www.example.com"],
             "urls": ["https://www.example.com/a", "https://WWW.example.com/b"],
             "ips": ["192.0.2.30"], "ip_attach_to": "www.example.com"},
            {"www.example.com": ["192.0.2.7"]}, dns)
        assert refused == []
        assert dns.asked == ["www.example.com"]
        assert config["user_targets"]["ip_attach_to"] == "www.example.com"

    def test_an_excluded_ip_entry_refuses_a_name_on_that_address(self, dns):
        _, refused = self._run({"subdomains": ["legacy.example.com", "www.example.com"]},
                               {"legacy.example.com": ["192.0.2.50"], "www.example.com": ["192.0.2.7"]},
                               dns, excluded=["192.0.2.50"])
        assert [RoE in r for r in refused] == [True]

    def test_a_switched_off_rule_set_resolves_nothing(self, dns):
        settings = dict(_settings(self.EXCLUDED), ROE_ENABLED=False)
        config = _config(settings, {"subdomains": ["legacy.example.com"]})
        assert filter_partial_user_input(config, settings) == []
        assert dns.asked == []


# --- through partial_recon.main and the real partial httpx -----------------------

class _NoGraph:
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return False


class _Stop(Exception):
    """Raised by the fake prober once it has the target list."""


@pytest.fixture
def pr(monkeypatch):
    import recon.partial_recon as module
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", "p1")
    monkeypatch.setattr("recon.graph_db_preflight.require_graph_db", lambda *_: None)
    monkeypatch.setattr(module, "_cleanup_orphan_user_inputs", lambda *_: 0)
    monkeypatch.setattr(module, "_legacy_graph_refusal", lambda settings, uid, pid: None)
    monkeypatch.setattr(module, "_apply_node_filters", lambda started_at: None)
    monkeypatch.setattr("graph_db.Neo4jClient", _NoGraph)
    return module


def _probed_by_partial_httpx(pr, monkeypatch, settings, config, resolved):
    """Run partial_recon.main for Httpx and return the by_host names the prober got."""
    monkeypatch.setattr("recon.partial_recon_modules.http_probing._resolve_hostname",
                        lambda host: resolved[host])
    probed = []

    def _probe(recon_data, output_file=None, settings=None):
        probed.append(sorted(recon_data["port_scan"]["by_host"]))
        raise _Stop()

    monkeypatch.setattr("recon.main_recon_modules.http_probe.run_http_probe", _probe)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(config, f)
    monkeypatch.setenv("PARTIAL_RECON_CONFIG", f.name)
    monkeypatch.setattr(pr, "get_settings", lambda: dict(settings))
    try:
        with pytest.raises(SystemExit):
            pr.main()
    finally:
        os.unlink(f.name)
    return probed


def test_partial_httpx_never_probes_a_typed_excluded_host(pr, monkeypatch, capsys, dns):
    settings = dict(DEFAULT_SETTINGS, TARGET_DOMAIN="example.com", SUBDOMAIN_LIST=["."],
                    SCOPE_GROUPS=[GROUP], ROE_ENABLED=True,
                    ROE_EXCLUDED_HOSTS=["legacy.example.com", "192.0.2.1"])
    config = {"tool_id": "Httpx", "domains": ["example.com"], "include_graph_targets": False,
              "user_targets": {"subdomains": ["legacy.example.com", "www.example.com"],
                               "ips": ["192.0.2.0/30"]}}
    dns.table = {"www.example.com": ["198.51.100.7"], "legacy.example.com": ["198.51.100.8"]}
    resolved = {"www.example.com": {"ipv4": ["198.51.100.7"], "ipv6": []},
                "legacy.example.com": {"ipv4": ["198.51.100.8"], "ipv6": []}}

    probed = _probed_by_partial_httpx(pr, monkeypatch, settings, config, resolved)

    assert probed == [["192.0.2.2", "www.example.com"]]
    out = capsys.readouterr().out
    assert out.count("'legacy.example.com'") == 1 and RoE in out


def test_partial_httpx_never_probes_a_typed_name_resolving_into_an_excluded_range(
        pr, monkeypatch, capsys, dns):
    # By name nothing is excluded here: only the address shows the RoE refuses it.
    settings = dict(DEFAULT_SETTINGS, TARGET_DOMAIN="example.com", SUBDOMAIN_LIST=["."],
                    SCOPE_GROUPS=[GROUP], ROE_ENABLED=True,
                    ROE_EXCLUDED_HOSTS=["198.51.100.0/24"])
    config = {"tool_id": "Httpx", "domains": ["example.com"], "include_graph_targets": False,
              "user_targets": {"subdomains": ["edge.example.com", "mixed.example.com",
                                              "www.example.com"]}}
    dns.table = {"edge.example.com": ["198.51.100.62"], "www.example.com": ["192.0.2.7"],
                 "mixed.example.com": ["192.0.2.8", "198.51.100.63"]}
    resolved = {name: {"ipv4": list(addrs), "ipv6": []} for name, addrs in dns.table.items()}

    probed = _probed_by_partial_httpx(pr, monkeypatch, settings, config, resolved)

    assert probed == [["www.example.com"]]
    out = capsys.readouterr().out
    assert out.count("'edge.example.com'") == 1 and out.count("'mixed.example.com'") == 1
    assert "198.51.100.62" in out and RoE in out
