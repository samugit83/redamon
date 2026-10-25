"""Nuclei that could not run is not a clean scan (C1), and each run owns its temp dir (C8).

C1 - when Docker or the templates are unavailable, only the Nuclei passes are
     skipped: the CVE lookup and the custom security checks still run, and the
     Nuclei sources are recorded as not re-checked, so the prune keeps their
     findings. A Nuclei container that exited non-zero for any reason but the
     runtime cap is recorded the same way, whatever it wrote first. A template
     UPDATE that times out is stopped, and Nuclei is skipped like an unavailable
     one, since the volume may be half-written.
C8 - the targets and JSONL files live in a directory unique to the run, so two
     concurrent scans sharing the /tmp/redamon bind mount never touch each
     other's files.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker as cb  # noqa: E402
from recon.helpers import docker_helpers  # noqa: E402
from recon.main_recon_modules import vuln_scan as vs  # noqa: E402

SECURITY_RESULT = {"security_checks": {"findings": [{"check": "missing_coop"}]}}


def _settings(**extra):
    base = {"NUCLEI_ENABLED": True, "NUCLEI_TAGS": ["cve"], "NUCLEI_AUTO_UPDATE_TEMPLATES": False,
            "CVE_LOOKUP_ENABLED": False, "SECURITY_CHECK_ENABLED": True,
            "NUCLEI_MAX_RUNTIME": 0}
    base.update(extra)
    return base


@pytest.fixture
def pipeline(monkeypatch):
    """Everything around the Nuclei passes, stubbed; the docker checks pass by default."""
    calls = {"passes": [], "security": 0, "cve": 0}

    def fake_pass(cmd, output_file, label, runtime_cap=0, container_name=None):
        calls["passes"].append({"output_file": output_file, "label": label,
                                "dir_exists": Path(output_file).parent.is_dir()})
        return [], [], 1.0, 0

    def fake_security(**kwargs):
        calls["security"] += 1
        return SECURITY_RESULT

    def fake_cve(**kwargs):
        calls["cve"] += 1
        return {"technology_cves": {"summary": {"total_cves": 0}}}

    monkeypatch.setattr(vs, "is_docker_installed", lambda: True)
    monkeypatch.setattr(vs, "is_docker_running", lambda: True)
    monkeypatch.setattr(vs, "pull_nuclei_docker_image", lambda image: True)
    monkeypatch.setattr(vs, "ensure_templates_volume", lambda image, auto: True)
    monkeypatch.setattr(vs, "extract_targets_from_recon", lambda rd: ([], ["www.example.com"], {}))
    monkeypatch.setattr(vs, "build_target_urls",
                        lambda h, i, rd, scan_all_ips=False: ["https://www.example.com"])
    monkeypatch.setattr(vs, "set_fp_ai_ctx", lambda **kw: None)
    monkeypatch.setattr(vs, "_execute_nuclei_pass", fake_pass)
    monkeypatch.setattr(vs, "run_security_checks", fake_security)
    monkeypatch.setattr(vs, "run_cve_lookup", fake_cve)
    return calls


def _recon():
    return {"domain": "example.com", "http_probe": {"by_url": {}}}


class TestNucleiUnavailable:
    @pytest.mark.parametrize("broken", ["is_docker_installed", "is_docker_running",
                                        "ensure_templates_volume"])
    def test_security_checks_still_run_and_nuclei_findings_are_kept(
            self, pipeline, monkeypatch, broken):
        monkeypatch.setattr(vs, broken, lambda *a: False)
        out = vs.run_vuln_scan(_recon(), settings=_settings())
        assert pipeline["passes"] == []
        assert pipeline["security"] == 1
        assert out["vuln_scan"]["security_checks"] == SECURITY_RESULT["security_checks"]
        report = cb.coverage_report()
        assert {"nuclei", "vuln_scan"} <= report.degraded_sources
        assert "security_check" not in report.degraded_sources

    def test_the_cve_lookup_still_runs(self, pipeline, monkeypatch):
        monkeypatch.setattr(vs, "is_docker_installed", lambda: False)
        vs.run_vuln_scan(_recon(), settings=_settings(CVE_LOOKUP_ENABLED=True))
        assert pipeline["cve"] == 1

    def test_the_isolated_wrapper_returns_the_security_checks(self, pipeline, monkeypatch):
        monkeypatch.setattr(vs, "is_docker_running", lambda: False)
        data = vs.run_vuln_scan_isolated(_recon(), _settings())
        assert data == {"vuln_scan": {"security_checks": SECURITY_RESULT["security_checks"]}}

    def test_a_healthy_scan_degrades_nothing(self, pipeline):
        out = vs.run_vuln_scan(_recon(), settings=_settings())
        assert [p["label"] for p in pipeline["passes"]] == ["DETECTION"]
        assert pipeline["security"] == 1
        assert out["vuln_scan"]["scan_metadata"]["execution_mode"] == "docker"
        assert not cb.coverage_report().degraded


class TestThePruneKeepsUncheckedNucleiFindings:
    @pytest.fixture
    def recon_main(self):
        stub = {
            'TARGET_DOMAIN': 'example.com', 'SUBDOMAIN_LIST': [], 'IP_MODE': False,
            'TARGET_IPS': [], 'DOMAIN_BATCH_MODE': False, 'DOMAIN_BATCH_GROUPS': [],
            'USE_BRUTEFORCE_FOR_SUBDOMAINS': False, 'SCAN_MODULES': ['domain_discovery'],
            'UPDATE_GRAPH_DB': True, 'USER_ID': 'u1', 'PROJECT_ID': 'p1',
            'VERIFY_DOMAIN_OWNERSHIP': False, 'STEALTH_MODE': False,
            'OWNERSHIP_TOKEN': '', 'OWNERSHIP_TXT_PREFIX': '',
        }
        with mock.patch('recon.project_settings.get_settings', return_value=dict(stub)):
            for mod in [m for m in list(sys.modules) if m in ('recon.main', 'main')]:
                del sys.modules[mod]
            import recon.main as rm
            rm._RUN_STARTED_AT = "2026-01-01T00:00:00+00:00"
            rm._COVERAGE_WRITE_FAILED = False
            yield rm

    def test_no_docker_prunes_security_checks_but_not_nuclei(self, recon_main, pipeline,
                                                              monkeypatch):
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
                prunes.append(list(sources))

        monkeypatch.setattr("graph_db.Neo4jClient", _Graph())
        monkeypatch.setattr(vs, "is_docker_installed", lambda: False)
        vs.run_vuln_scan(_recon(), settings=_settings())
        recon_main._prune_recon_findings()
        (sources,) = prunes
        assert "nuclei" not in sources and "vuln_scan" not in sources
        assert "security_check" in sources


class _Proc:
    def __init__(self, rc, lines=("[INF] done",)):
        self.returncode = rc
        self.stdout = iter(lines)

    def wait(self):
        return self.returncode


class TestNucleiExitCode:
    def _pass(self, monkeypatch, tmp_path, rc, jsonl=None):
        out = tmp_path / "o.jsonl"
        if jsonl is not None:
            out.write_text(jsonl)
        monkeypatch.setattr(vs.subprocess, "Popen", lambda *a, **k: _Proc(rc))
        return vs._execute_nuclei_pass(["docker", "run"], str(out), label="DETECTION")

    def test_a_failed_container_with_no_output_keeps_nuclei_findings(self, monkeypatch, tmp_path):
        findings, _, _, rc = self._pass(monkeypatch, tmp_path, 125)
        assert findings == [] and rc == 125
        assert {"nuclei", "vuln_scan"} <= cb.coverage_report().degraded_sources

    def test_a_crash_with_only_unparseable_output_keeps_nuclei_findings(self, monkeypatch, tmp_path):
        self._pass(monkeypatch, tmp_path, 1, jsonl="not json\n")
        assert "nuclei" in cb.coverage_report().degraded_sources

    def test_a_clean_run_with_no_findings_is_a_clean_scan(self, monkeypatch, tmp_path):
        self._pass(monkeypatch, tmp_path, 0, jsonl="")
        assert not cb.coverage_report().degraded

    def test_a_non_zero_exit_that_still_wrote_findings_keeps_the_rest(self, monkeypatch, tmp_path):
        line = '{"template-id":"x","matched-at":"https://a.test","info":{"severity":"low"}}\n'
        findings, _, _, _ = self._pass(monkeypatch, tmp_path, 1, jsonl=line)
        assert len(findings) == 1
        assert {"nuclei", "vuln_scan"} <= cb.coverage_report().degraded_sources


class TestTemplateUpdateTimeout:
    def _run(self, monkeypatch, *, volume_exists, template_count="5", update_raises=False,
             count_raises=False):
        commands = []

        def fake_run(cmd, **kwargs):
            commands.append(cmd)
            if cmd[:3] == ["docker", "volume", "inspect"]:
                return subprocess.CompletedProcess(cmd, 0 if volume_exists else 1, "", "")
            if cmd[:3] == ["docker", "volume", "create"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if cmd[:2] == ["docker", "kill"]:
                return subprocess.CompletedProcess(cmd, 0, "", "")
            if "alpine" in cmd:
                if count_raises:
                    raise subprocess.TimeoutExpired(cmd, 30)
                return subprocess.CompletedProcess(cmd, 0, template_count, "")
            if "-ut" in cmd:
                if update_raises:
                    raise subprocess.TimeoutExpired(cmd, 600)
                return subprocess.CompletedProcess(cmd, 0, "", "")
            raise AssertionError(f"unexpected command {cmd}")

        monkeypatch.setattr(docker_helpers.subprocess, "run", fake_run)
        return docker_helpers.ensure_templates_volume("projectdiscovery/nuclei:latest",
                                                      auto_update=True), commands

    def test_an_update_timeout_over_existing_templates_skips_nuclei(self, monkeypatch):
        ok, commands = self._run(monkeypatch, volume_exists=True, update_raises=True)
        assert ok is False
        assert any("-ut" in c for c in commands)
        assert any(c[:2] == ["docker", "kill"] for c in commands)

    def test_a_first_download_that_times_out_has_no_templates(self, monkeypatch):
        ok, _ = self._run(monkeypatch, volume_exists=False, update_raises=True)
        assert ok is False

    def test_an_empty_volume_whose_download_times_out_has_no_templates(self, monkeypatch):
        ok, _ = self._run(monkeypatch, volume_exists=True, template_count="0", update_raises=True)
        assert ok is False

    def test_a_template_count_timeout_is_still_a_failure(self, monkeypatch):
        ok, _ = self._run(monkeypatch, volume_exists=True, count_raises=True)
        assert ok is False

    def test_a_healthy_update_is_unchanged(self, monkeypatch):
        ok, _ = self._run(monkeypatch, volume_exists=True)
        assert ok is True


class TestPerRunTempDir:
    _DIR = re.compile(r"^/tmp/redamon/\.nuclei_temp_[0-9a-f]{32}$")

    def test_each_run_writes_in_its_own_directory_and_removes_it(self, pipeline):
        vs.run_vuln_scan(_recon(), settings=_settings())
        vs.run_vuln_scan(_recon(), settings=_settings())
        first, second = (Path(p["output_file"]).parent for p in pipeline["passes"])
        assert self._DIR.match(str(first)) and self._DIR.match(str(second))
        assert first != second
        assert all(p["dir_exists"] for p in pipeline["passes"])
        assert not first.exists() and not second.exists()

    def test_another_runs_files_are_left_alone(self, pipeline):
        shared = Path("/tmp/redamon/.nuclei_temp")
        shared.mkdir(parents=True, exist_ok=True)
        other = shared / "nuclei_detection.jsonl"
        other.write_text('{"template-id":"other-run"}\n')
        try:
            vs.run_vuln_scan(_recon(), settings=_settings())
            assert other.read_text() == '{"template-id":"other-run"}\n'
        finally:
            other.unlink(missing_ok=True)
            try:
                shared.rmdir()
            except OSError:
                pass

    def test_a_skipped_detection_pass_leaves_no_directory_behind(self, pipeline):
        before = set(Path("/tmp/redamon").glob(".nuclei_temp_*"))
        vs.run_vuln_scan(_recon(), settings=_settings(NUCLEI_TAGS=[]))
        assert pipeline["passes"] == []
        assert set(Path("/tmp/redamon").glob(".nuclei_temp_*")) == before
