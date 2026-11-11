"""Regression: two Nuclei early returns skipped the CVE lookup and the security checks.

With empty Include Tags, no custom template and no DAST pass, and when the
recon data held no target at all, run_vuln_scan returned before the CVE
lookup and the custom security checks. Nothing was recorded, so the prune
deleted every security_check finding (SPF/DMARC/DNSSEC on the root domain
included). Now only the Nuclei passes are skipped.

Nuclei left with no template to run by its configuration re-checked none of
its findings, so they are kept. With no target at all the run resolved no
host, which is the same evidence every other scanner's empty result is
taken as, so nothing is recorded and the prune behaves as before.

The Nuclei passes, the CVE lookup and the security checks are fakes.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

SECURITY = {"security_checks": {"findings": [{"check": "spf_missing"}]}}


def _settings(**extra):
    base = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
            "CVE_LOOKUP_ENABLED": True, "SECURITY_CHECK_ENABLED": True, "NUCLEI_MAX_RUNTIME": 0}
    base.update(extra)
    return base


def _recon():
    return {"domain": "example.com", "http_probe": {"by_url": {}},
            "resource_enum": {"discovered_urls": ["https://www.example.com/p?id=1"]}}


@pytest.fixture
def pipeline(monkeypatch):
    calls = {"passes": [], "security": 0, "cve": 0, "targets": ([], ["www.example.com"], {})}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        calls["passes"].append(label)
        return [], [], 1.0, 0

    def fake_security(**kwargs):
        calls["security"] += 1
        return SECURITY

    def fake_cve(**kwargs):
        calls["cve"] += 1
        return {"technology_cves": {"summary": {"total_cves": 0}}}

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd, *_a, **_k: calls["targets"])
    monkeypatch.setattr(vs, "build_target_urls",
                        lambda h, i, rd, scan_all_ips=False: ["https://www.example.com"])
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    monkeypatch.setattr(vs, "run_security_checks", fake_security)
    monkeypatch.setattr(vs, "run_cve_lookup", fake_cve)
    return calls


class TestRegressionNucleiEarlyReturns:
    def test_regression_nuclei_empty_tags_skipped_security_checks(self, pipeline):
        out = vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_TAGS=[]))
        assert pipeline["passes"] == []
        assert pipeline["cve"] == 1 and pipeline["security"] == 1
        assert out["vuln_scan"]["security_checks"] == SECURITY["security_checks"]
        report = cb.coverage_report()
        assert {"nuclei", "vuln_scan"} <= report.degraded_sources
        assert "security_check" not in report.degraded_sources

    def test_regression_nuclei_no_targets_skipped_security_checks(self, pipeline):
        pipeline["targets"] = (set(), set(), {})
        out = vs.run_vuln_scan(_recon(), settings=_settings())
        assert pipeline["passes"] == []
        assert pipeline["cve"] == 1 and pipeline["security"] == 1
        assert out["vuln_scan"]["security_checks"] == SECURITY["security_checks"]
        assert not cb.coverage_report().degraded

    def test_empty_tags_with_a_dast_pass_still_runs_it_and_records_nothing(self, pipeline):
        vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_TAGS=[], NUCLEI_DAST_MODE=True))
        assert pipeline["passes"] == ["DAST"]
        assert pipeline["security"] == 1
        assert not cb.coverage_report().degraded

    def test_a_healthy_scan_is_unchanged(self, pipeline):
        out = vs.run_vuln_scan(_recon(), settings=_settings())
        assert pipeline["passes"] == ["DETECTION"]
        assert pipeline["cve"] == 1 and pipeline["security"] == 1
        assert out["vuln_scan"]["scan_metadata"]["execution_mode"] == "docker"
        assert not cb.coverage_report().degraded

    def test_the_prune_then_keeps_nuclei_and_prunes_the_checks(self, pipeline):
        stub = {
            'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
            'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
            'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
            'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        }
        prunes = []

        class _Graph:
            def __call__(self, *a, **k):
                return self

            def __enter__(self):
                return self

            def __exit__(self, *exc):
                return False

            def verify_connection(self):
                return True

            def prune_unseen_findings(self, user_id, project_id, sources, since, keep_hosts=()):
                prunes.extend(sources)

        with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)), \
                mock.patch("graph_db.Neo4jClient", _Graph()):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
            rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
            rm._COVERAGE_WRITE_FAILED = False
            vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_TAGS=[]))
            rm._prune_recon_findings()
        assert "security_check" in prunes
        assert "nuclei" not in prunes and "vuln_scan" not in prunes
