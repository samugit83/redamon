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

Reserved names and documentation ranges only.
"""
import json
import os
import sys
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


def _filter(project, typed):
    roots = ["ip-targets.p1"] if project.get("ipMode") else ["example.com"]
    targets = {k: v for k, v in typed.items() if k != "user_inputs"}
    return filter_partial_user_input(project, roots, list(typed.get("user_inputs", [])), targets)


def test_the_tables_are_present_and_real():
    if not _MATCHER_PATH.exists() or not _FILTER_PATH.exists():
        pytest.skip(f"recon fixtures not mounted ({_FIXTURES})")
    assert len(_MATCHER) >= 40
    assert len(_FILTER) >= 15


@pytest.mark.parametrize("v", _MATCHER, ids=[v["name"] for v in _MATCHER])
def test_matcher_vector(v):
    assert batch_scope.is_roe_excluded(v["host"], v["excluded"]) is v["result"]


@pytest.mark.parametrize("v", _FILTER, ids=[v["name"] for v in _FILTER])
def test_filter_vector(v):
    inputs, targets, refused = _filter(_project(v["excluded"], v.get("ip_mode", False)), v["typed"])
    got = dict(targets, user_inputs=inputs)
    for key, expected in v["kept"].items():
        assert got.get(key) == expected, key
    assert sum(RoE in r for r in refused) == v["roe_refused"], refused


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
