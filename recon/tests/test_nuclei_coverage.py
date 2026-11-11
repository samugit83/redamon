"""Nuclei records, per web host, what it scanned (plan 09.1).

run_vuln_scan writes ``vuln_scan.scan_metadata.coverage = {"at", "hosts"}``:
one row per web host a Nuclei pass targeted, with how many of its URLs were
sent and how many findings came back. A pass stopped by NUCLEI_MAX_RUNTIME
leaves its hosts ``partial`` (the run never says which targets it reached), a
pass that died with nothing parsed leaves them ``failed``, and a Nuclei that
was meant to run but could not leaves every live host ``failed`` with the
reason. Nuclei switched off stamps nothing: it was never meant to look.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers.coverage_stamps import base_url_key  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

APP, WWW = "app.example.com", "www.example.com"
TARGETS = [f"https://{APP}", f"https://{APP}/login?next=1", f"https://{WWW}"]


def _settings(**extra):
    base = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
            "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": False, "NUCLEI_MAX_RUNTIME": 0}
    base.update(extra)
    return base


def _finding(url):
    return {"template_id": "t1", "name": "T", "severity": "low", "target": url, "matched_at": url,
            "category": "misc", "cves": [], "cvss_score": None}


@pytest.fixture
def pipeline(monkeypatch):
    state = {"result": ([], [], 1.0, 0), "passes": []}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        state["passes"].append(label)
        return state["result"]

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd, *_a, **_k: ([], [APP, WWW], {}))
    monkeypatch.setattr(vs, "build_target_urls", lambda h, i, rd, scan_all_ips=False: list(TARGETS))
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    return state


def _recon():
    return {"domain": "example.com",
            "http_probe": {"by_url": {f"https://{APP}": {"status_code": 200},
                                      f"https://{WWW}": {"status_code": 200}}}}


def _coverage(out):
    return out["vuln_scan"]["scan_metadata"]["coverage"]


def _row(cov, host):
    return cov["hosts"].get(base_url_key(f"https://{host}"))


def test_a_clean_pass_marks_every_targeted_host_complete_with_its_urls(pipeline):
    pipeline["result"] = ([_finding(f"https://{APP}/login?next=1")], [], 3.0, 0)
    cov = _coverage(vs.run_vuln_scan(_recon(), settings=_settings()))
    assert _row(cov, APP) == {"status": "complete", "inputs": 2, "outputs": 1, "reason": None}
    assert _row(cov, WWW) == {"status": "complete", "inputs": 1, "outputs": 0, "reason": None}
    assert cov["at"]


def test_a_pass_stopped_by_the_runtime_cap_leaves_its_hosts_partial(pipeline):
    pipeline["result"] = ([_finding(f"https://{APP}")], [], 3600.4, 137)
    cov = _coverage(vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_MAX_RUNTIME=3600)))
    assert _row(cov, APP) == {"status": "partial", "inputs": 2, "outputs": 1, "reason": "runtime cap"}
    assert _row(cov, WWW)["status"] == "partial"


def test_a_pass_that_died_with_nothing_parsed_failed(pipeline):
    pipeline["result"] = ([], [], 2.0, 125)
    cov = _coverage(vs.run_vuln_scan(_recon(), settings=_settings()))
    assert _row(cov, APP) == {"status": "failed", "inputs": 2, "outputs": 0, "reason": "nuclei exited 125"}


def test_a_pass_that_died_after_some_results_is_partial(pipeline):
    pipeline["result"] = ([_finding(f"https://{WWW}")], [], 2.0, 1)
    cov = _coverage(vs.run_vuln_scan(_recon(), settings=_settings()))
    assert _row(cov, WWW) == {"status": "partial", "inputs": 1, "outputs": 1, "reason": "nuclei exited 1"}


def test_the_dast_pass_adds_its_urls_and_one_failing_pass_makes_the_host_partial(pipeline, monkeypatch):
    results = iter([([], [], 1.0, 0), ([], [], 1.0, 125)])
    monkeypatch.setattr(vs, "_execute_nuclei_pass",
                        lambda cmd, output_file, label, runtime_cap=0, container_name=None: next(results))
    recon = dict(_recon(), resource_enum={"discovered_urls": [f"https://{APP}/search?q=1"]})
    cov = _coverage(vs.run_vuln_scan(recon, settings=_settings(NUCLEI_DAST_MODE=True)))
    assert _row(cov, APP) == {"status": "partial", "inputs": 3, "outputs": 0, "reason": "nuclei exited 125"}
    assert _row(cov, WWW)["status"] == "complete"


@pytest.mark.parametrize("broken,reason", [
    ("is_docker_installed", "Docker not found"),
    ("ensure_templates_volume", "nuclei templates unavailable"),
])
def test_a_nuclei_that_could_not_run_fails_every_live_host(pipeline, monkeypatch, broken, reason):
    monkeypatch.setattr(vs, broken, lambda *a: False)
    cov = _coverage(vs.run_vuln_scan(_recon(), settings=_settings()))
    assert pipeline["passes"] == []
    assert _row(cov, APP) == {"status": "failed", "inputs": 0, "outputs": 0, "reason": reason}
    assert _row(cov, WWW)["status"] == "failed"


def test_no_template_selected_fails_the_targeted_hosts(pipeline):
    cov = _coverage(vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_TAGS=[])))
    assert _row(cov, APP) == {"status": "failed", "inputs": 0, "outputs": 0,
                              "reason": "no Nuclei templates selected"}


def test_nuclei_switched_off_stamps_nothing(pipeline):
    out = vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_ENABLED=False))
    assert "coverage" not in out["vuln_scan"]["scan_metadata"]


def test_a_host_no_pass_targeted_gets_no_row(pipeline):
    recon = _recon()
    recon["http_probe"]["by_url"]["https://other.example.com"] = {"status_code": 200}
    cov = _coverage(vs.run_vuln_scan(recon, settings=_settings()))
    assert _row(cov, "other.example.com") is None
