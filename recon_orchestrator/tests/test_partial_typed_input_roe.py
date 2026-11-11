"""batch_scope.filter_partial_user_input against the RoE exclusion list (R-6).

The job queue and the scan scheduler post partial runs here directly, past the
modal, so the orchestrator drops a typed host, URL, address or attach target
the client excluded before the container starts. This image carries no
recon/, so it keeps a copy of recon/helpers/roe_scope.py's matcher and of the
recon-side filter; both copies run the shared tables:

  - recon/tests/fixtures/roe_exclusion_vectors.json (the matcher; also run by
    recon, the agent and the webapp),
  - recon/tests/fixtures/partial_typed_input_roe_vectors.json (the filter; also
    run by recon/tests/test_partial_typed_input_roe.py).

Under RoE IP or CIDR entries a typed name is refused here too when an address it
resolves to is excluded. This service resolves from the compose network, not
from the host network the scan runs on, so a name it gets no answer for is left
to the container, which resolves as the tools do and refuses it there.
DNS is a fake socket.getaddrinfo serving each vector's 'resolved' map.

Reserved names and documentation ranges only.
"""
import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import batch_scope  # noqa: E402
from batch_scope import filter_partial_user_input  # noqa: E402

_FIXTURES = Path(__file__).resolve().parents[2] / "recon" / "tests" / "fixtures"
_MATCHER_PATH = _FIXTURES / "roe_exclusion_vectors.json"
_FILTER_PATH = _FIXTURES / "partial_typed_input_roe_vectors.json"


def _load(path):
    return json.loads(path.read_text())["vectors"] if path.exists() else []


_MATCHER = _load(_MATCHER_PATH)
_FILTER = _load(_FILTER_PATH)

GROUP = {"scanRoot": "example.com", "orgDomain": "example.com", "mode": "enumerate",
         "includeRoot": True, "exactHosts": []}
TARGET_IPS = ["192.0.2.10", "192.0.2.11"]
RoE = "Rules of Engagement"


def _project(excluded, ip_mode=False):
    if ip_mode:
        return {"ipMode": True, "targetIps": TARGET_IPS, "roeExcludedHosts": list(excluded)}
    return {"targetDomain": "example.com", "scopeGroups": [GROUP], "roeExcludedHosts": list(excluded)}


def _filter(project, typed, **kwargs):
    roots = ["ip-targets.p1"] if project.get("ipMode") else ["example.com"]
    targets = {k: v for k, v in typed.items() if k != "user_inputs"}
    return filter_partial_user_input(project, roots, list(typed.get("user_inputs", [])), targets,
                                     **kwargs)


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


def test_the_tables_are_present_and_real():
    if not _MATCHER_PATH.exists() or not _FILTER_PATH.exists():
        pytest.skip(f"recon fixtures not mounted ({_FIXTURES})")
    assert len(_MATCHER) >= 40
    assert len(_FILTER) >= 15
    assert sum("resolved" in v and not v.get("no_lookup") for v in _FILTER) >= 7


@pytest.mark.parametrize("v", _MATCHER, ids=[v["name"] for v in _MATCHER])
def test_matcher_vector(v):
    assert batch_scope.is_roe_excluded(v["host"], v["excluded"]) is v["result"]


@pytest.mark.parametrize("v", _FILTER, ids=[v["name"] for v in _FILTER])
def test_filter_vector(v, dns):
    dns.table = dict(v.get("resolved") or {})
    inputs, targets, refused = _filter(_project(v["excluded"], v.get("ip_mode", False)), v["typed"])
    got = dict(targets, user_inputs=inputs)
    # Only where the table says so does this copy's verdict differ from the
    # container's: a name with no answer here is the container's to refuse.
    verdict = dict(v, **v.get("orchestrator", {}))
    for key, expected in verdict["kept"].items():
        assert got.get(key) == expected, key
    assert sum(RoE in r for r in refused) == verdict["roe_refused"], refused
    if v.get("no_lookup"):
        assert dns.asked == []


def test_the_copies_part_only_on_a_name_with_no_answer():
    # The one divergence the table allows is the orchestrator keeping a name
    # the container refuses for want of an address; never the other way.
    for v in _FILTER:
        if "orchestrator" not in v:
            continue
        unanswered = {n for key in ("subdomains", "user_inputs") for n in v["typed"].get(key, [])
                      if n not in (v.get("resolved") or {})}
        assert unanswered, v["name"]
        for key, kept in v["orchestrator"]["kept"].items():
            assert set(v["kept"][key]) <= set(kept), v["name"]
            assert set(kept) - set(v["kept"][key]) <= unanswered, v["name"]


class TestAddressRefusals:
    def test_the_refusal_names_the_excluded_address(self, dns):
        dns.table = {"legacy.example.com": ["198.51.100.20"], "mixed.example.com": ["192.0.2.8", "198.51.100.21"]}
        inputs, targets, refused = _filter(_project(["198.51.100.0/24"]),
                                           {"subdomains": ["legacy.example.com"],
                                            "urls": ["https://mixed.example.com/x"]})
        assert targets["subdomains"] == [] and targets["urls"] == []
        assert len(refused) == 2 and all(RoE in r for r in refused)
        assert "198.51.100.20" in refused[0]
        assert "198.51.100.21" in refused[1] and "192.0.2.8" not in refused[1]

    def test_a_name_is_resolved_once_whatever_lists_carry_it(self, dns):
        dns.table = {"www.example.com": ["192.0.2.7"]}
        inputs, targets, refused = _filter(
            _project(["198.51.100.0/24"]),
            {"user_inputs": ["www.example.com"], "subdomains": ["WWW.example.com"],
             "urls": ["https://www.example.com/a"], "ips": ["192.0.2.30"],
             "ip_attach_to": "www.example.com"})
        assert refused == []
        assert dns.asked == ["www.example.com"]

    def test_a_slow_resolver_leaves_the_name_to_the_container(self, dns, monkeypatch):
        # The filter runs inside the start request: a resolver that hangs must
        # cost the request its DNS budget at most, and refuse nothing.
        release = threading.Event()

        def hang(host, *args, **kwargs):
            release.wait(5)
            raise socket.gaierror(socket.EAI_AGAIN, "timeout")

        monkeypatch.setattr(socket, "getaddrinfo", hang)
        started = time.monotonic()
        try:
            inputs, targets, refused = _filter(
                _project(["198.51.100.0/24"]),
                {"subdomains": ["a.example.com", "b.example.com", "c.example.com"]},
                dns_budget_s=0.3)
        finally:
            release.set()
        assert time.monotonic() - started < 2
        assert targets["subdomains"] == ["a.example.com", "b.example.com", "c.example.com"]
        assert refused == []


def test_the_exclusion_list_applies_whatever_the_stored_roe_switch_says():
    # roeEnabled is derived from the limits (recon_settings.engagement), never
    # read: a stale false in the column must not let an excluded host through.
    project = dict(_project(["legacy.example.com"]), roeEnabled=False)
    inputs, targets, refused = _filter(project, {"user_inputs": ["legacy.example.com"],
                                                 "subdomains": ["legacy.example.com"]})
    assert inputs == [] and targets["subdomains"] == []
    assert sum(RoE in r for r in refused) == 2


def test_a_project_without_the_field_excludes_nothing():
    project = {"targetDomain": "example.com", "scopeGroups": [GROUP]}
    inputs, targets, refused = _filter(project, {"subdomains": ["legacy.example.com"],
                                                 "ips": ["192.0.2.0/29"]})
    assert targets == {"subdomains": ["legacy.example.com"], "ips": ["192.0.2.0/29"]}
    assert refused == []
