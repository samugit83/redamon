"""A partial run's typed input against the RoE exclusion list (R-6, typed half).

The graph builders drop RoE-excluded hosts and IPs (30cf1a57); what the
operator types reached the tools with a scope check only, so a host the client
excluded after a full scan was still probed when typed into the partial modal,
and a typed IP or CIDR was checked for width alone. filter_partial_user_input
now drops an excluded host, URL, IP or attach target, keeps the other hosts of
a typed CIDR that holds an excluded address, names the Rules of Engagement in
each refusal and records one `roe_excluded` coverage note.

The table in fixtures/partial_typed_input_roe_vectors.json is also run against
the orchestrator's copy (recon_orchestrator/tests/test_partial_typed_input_roe.py),
which filters the same payload before the container starts.
Reserved names and documentation ranges only.
"""
import json
import os
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


def test_the_table_is_real():
    assert len(VECTORS) >= 15
    assert sum(v["roe_refused"] for v in VECTORS) >= 15


@pytest.mark.parametrize("v", VECTORS, ids=[v["name"] for v in VECTORS])
def test_vector(v):
    settings = _settings(v["excluded"], v.get("ip_mode", False))
    config = _config(settings, v["typed"])
    refused = filter_partial_user_input(config, settings)
    got = dict(config["user_targets"], user_inputs=config["user_inputs"])
    for key, expected in v["kept"].items():
        assert got.get(key) == expected, key
    assert sum(RoE in r for r in refused) == v["roe_refused"], refused


class TestTheRefusalIsRecorded:
    def _roe_gaps(self):
        return [g for g in circuit_breaker.coverage_report().gaps
                if g.get("source") == "roe_excluded"]

    def test_one_coverage_note_counts_every_excluded_input(self):
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

    def test_a_switched_off_rule_set_excludes_nothing(self):
        settings = dict(_settings(["legacy.example.com"]), ROE_ENABLED=False)
        config = _config(settings, {"subdomains": ["legacy.example.com"]})
        assert filter_partial_user_input(config, settings) == []
        assert config["user_targets"]["subdomains"] == ["legacy.example.com"]


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


def test_partial_httpx_never_probes_a_typed_excluded_host(pr, monkeypatch, capsys):
    settings = dict(DEFAULT_SETTINGS, TARGET_DOMAIN="example.com", SUBDOMAIN_LIST=["."],
                    SCOPE_GROUPS=[GROUP], ROE_ENABLED=True,
                    ROE_EXCLUDED_HOSTS=["legacy.example.com", "192.0.2.1"])
    config = {"tool_id": "Httpx", "domains": ["example.com"], "include_graph_targets": False,
              "user_targets": {"subdomains": ["legacy.example.com", "www.example.com"],
                               "ips": ["192.0.2.0/30"]}}
    resolved = {"www.example.com": {"ipv4": ["198.51.100.7"], "ipv6": []},
                "legacy.example.com": {"ipv4": ["198.51.100.8"], "ipv6": []}}
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

    assert probed == [["192.0.2.2", "www.example.com"]]
    out = capsys.readouterr().out
    assert out.count("'legacy.example.com'") == 1 and RoE in out
