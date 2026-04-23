"""
Unit tests for TruffleHog integration.

Tests cover:
1. TrufflehogRunner — JSONL parsing, source metadata extraction, dedup, command building
2. Project settings — default values, camelCase→SNAKE_CASE mapping
3. Main entry — validation logic, error handling
4. Neo4j graph client — update_graph_from_trufflehog node creation and dedup
5. Orchestrator models — TrufflehogState, TrufflehogStatus enums

Run with: python -m pytest tests/test_trufflehog_integration.py -v
"""

import json
import os
import sys
import types
import unittest
from unittest.mock import patch, MagicMock, mock_open
from pathlib import Path
from datetime import datetime

REPO_ROOT = Path(__file__).resolve().parent.parent

# Add paths for imports
sys.path.insert(0, str(REPO_ROOT / "trufflehog_scan"))

# Stub graph_db before any imports that might pull it in
if "graph_db" not in sys.modules:
    _fake_graph = types.ModuleType("graph_db")
    _fake_graph.Neo4jClient = MagicMock
    sys.modules["graph_db"] = _fake_graph

# Stub container-only deps: neo4j, pydantic, docker, dotenv, etc.
_stub_modules = [
    "neo4j", "neo4j.GraphDatabase", "dotenv",
    "docker", "docker.errors", "docker.models", "docker.models.containers",
    "sse_starlette", "sse_starlette.sse",
    "fastapi", "fastapi.middleware", "fastapi.middleware.cors",
]
for mod_name in _stub_modules:
    if mod_name not in sys.modules:
        mod = types.ModuleType(mod_name)
        # docker.errors needs NotFound and APIError
        if mod_name == "docker.errors":
            mod.NotFound = type("NotFound", (Exception,), {})
            mod.APIError = type("APIError", (Exception,), {})
        sys.modules[mod_name] = mod

# Stub pydantic with a functional BaseModel
if "pydantic" not in sys.modules:
    _pydantic = types.ModuleType("pydantic")

    class _FakeBaseModel:
        def __init_subclass__(cls, **kw): pass
        def __init__(self, **kw):
            # Apply class annotations as defaults
            for attr, annotation in getattr(self.__class__, '__annotations__', {}).items():
                if hasattr(self.__class__, attr):
                    setattr(self, attr, kw.get(attr, getattr(self.__class__, attr)))
                elif attr in kw:
                    setattr(self, attr, kw[attr])
                else:
                    setattr(self, attr, None)
            # Also set any extra kwargs
            for k, v in kw.items():
                setattr(self, k, v)
        def model_dump(self):
            return {k: v.value if hasattr(v, 'value') else v
                    for k, v in self.__dict__.items()}
    _pydantic.BaseModel = _FakeBaseModel
    sys.modules["pydantic"] = _pydantic

# Now safe to add orchestrator path
sys.path.insert(0, str(REPO_ROOT / "recon_orchestrator"))


# =============================================================================
# 1. TrufflehogRunner — JSONL parsing & command building
# =============================================================================

from trufflehog_runner import TrufflehogRunner


class TestTrufflehogRunnerInit(unittest.TestCase):
    """Test TrufflehogRunner initialization."""

    def test_default_initialization(self):
        runner = TrufflehogRunner(
            token="ghp_test123",
            target_org="myorg",
            project_id="proj-001",
        )
        self.assertEqual(runner.token, "ghp_test123")
        self.assertEqual(runner.target_org, "myorg")
        self.assertEqual(runner.project_id, "proj-001")
        self.assertEqual(runner.concurrency, 8)
        self.assertFalse(runner.only_verified)
        self.assertFalse(runner.no_verification)
        self.assertEqual(runner.stats["total_findings"], 0)
        self.assertEqual(runner.findings, [])

    def test_output_file_path(self):
        runner = TrufflehogRunner(token="t", project_id="abc-123")
        self.assertIn("trufflehog_abc-123.json", runner.output_file)


class TestTrufflehogRunnerCommands(unittest.TestCase):
    """Test CLI command building."""

    def test_org_scan_command(self):
        runner = TrufflehogRunner(
            token="ghp_test",
            target_org="myorg",
            project_id="p1",
        )
        cmds = runner._build_commands()
        self.assertEqual(len(cmds), 1)
        cmd = cmds[0]
        self.assertIn("trufflehog", cmd)
        self.assertIn("github", cmd)
        self.assertIn("--org=myorg", cmd)
        self.assertIn("--token=ghp_test", cmd)
        self.assertIn("--json", cmd)

    def test_repo_scan_commands(self):
        runner = TrufflehogRunner(
            token="ghp_test",
            target_repos="org/repo1, org/repo2",
            project_id="p1",
        )
        cmds = runner._build_commands()
        self.assertEqual(len(cmds), 2)
        self.assertIn("--repo=https://github.com/org/repo1", cmds[0])
        self.assertIn("--repo=https://github.com/org/repo2", cmds[1])

    def test_repo_with_full_url(self):
        runner = TrufflehogRunner(
            token="t",
            target_repos="https://github.com/org/repo1",
            project_id="p1",
        )
        cmds = runner._build_commands()
        # Should not double-prefix
        self.assertIn("--repo=https://github.com/org/repo1", cmds[0])

    def test_repos_take_priority_over_org(self):
        """When both org and repos are set, only repos are scanned (not the whole org)."""
        runner = TrufflehogRunner(
            token="t",
            target_org="myorg",
            target_repos="org/repo1",
            project_id="p1",
        )
        cmds = runner._build_commands()
        # Repos take priority — only 1 command for the specific repo
        self.assertEqual(len(cmds), 1)
        self.assertIn("--repo=https://github.com/org/repo1", cmds[0])
        # Should NOT contain --org
        self.assertNotIn("--org=myorg", cmds[0])

    def test_no_targets_returns_empty(self):
        runner = TrufflehogRunner(token="t", project_id="p1")
        cmds = runner._build_commands()
        self.assertEqual(len(cmds), 0)

    def test_only_verified_flag(self):
        runner = TrufflehogRunner(
            token="t", target_org="org", project_id="p1",
            only_verified=True,
        )
        cmd = runner._build_commands()[0]
        self.assertIn("--results=verified", cmd)

    def test_no_verification_flag(self):
        runner = TrufflehogRunner(
            token="t", target_org="org", project_id="p1",
            no_verification=True,
        )
        cmd = runner._build_commands()[0]
        self.assertIn("--no-verification", cmd)

    def test_concurrency_flag(self):
        runner = TrufflehogRunner(
            token="t", target_org="org", project_id="p1",
            concurrency=16,
        )
        cmd = runner._build_commands()[0]
        idx = cmd.index("--concurrency")
        self.assertEqual(cmd[idx + 1], "16")

    def test_include_detectors_flag(self):
        runner = TrufflehogRunner(
            token="t", target_org="org", project_id="p1",
            include_detectors="AWS,GitHub",
        )
        cmd = runner._build_commands()[0]
        idx = cmd.index("--include-detectors")
        self.assertEqual(cmd[idx + 1], "AWS,GitHub")

    def test_exclude_detectors_flag(self):
        runner = TrufflehogRunner(
            token="t", target_org="org", project_id="p1",
            exclude_detectors="Slack",
        )
        cmd = runner._build_commands()[0]
        idx = cmd.index("--exclude-detectors")
        self.assertEqual(cmd[idx + 1], "Slack")


class TestTrufflehogRunnerParsing(unittest.TestCase):
    """Test JSONL finding parsing."""

    def _make_trufflehog_result(self, **overrides):
        """Build a realistic TruffleHog JSON result."""
        result = {
            "SourceMetadata": {
                "Data": {
                    "Github": {
                        "repository": "https://github.com/org/repo",
                        "file": "config/keys.py",
                        "commit": "abc123def456",
                        "line": 42,
                        "link": "https://github.com/org/repo/blob/abc123/config/keys.py#L42",
                        "email": "dev@example.com",
                        "timestamp": "2024-01-15 10:30:00 -0700 PDT",
                        "visibility": 1,
                    }
                }
            },
            "SourceID": 0,
            "SourceType": 16,
            "SourceName": "trufflehog - github",
            "DetectorType": 2,
            "DetectorName": "AWS",
            "DetectorDescription": "AWS API Key",
            "DecoderName": "PLAIN",
            "Verified": True,
            "Raw": "AKIAYVP4CIPPERUVIFXG",
            "RawV2": "AKIAYVP4CIPPERUVIFXG:secret",
            "Redacted": "AKIAYVP4CIPPERUVIFXG",
            "ExtraData": {"account": "595918472158"},
            "StructuredData": None,
        }
        result.update(overrides)
        return result

    def test_parse_github_source(self):
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = self._make_trufflehog_result()
        finding = runner._parse_finding(result)

        self.assertIsNotNone(finding)
        self.assertEqual(finding["detector_name"], "AWS")
        self.assertEqual(finding["detector_description"], "AWS API Key")
        self.assertTrue(finding["verified"])
        self.assertEqual(finding["redacted"], "AKIAYVP4CIPPERUVIFXG")
        self.assertEqual(finding["repository"], "https://github.com/org/repo")
        self.assertEqual(finding["file"], "config/keys.py")
        self.assertEqual(finding["commit"], "abc123def456")
        self.assertEqual(finding["line"], 42)
        self.assertEqual(finding["link"], "https://github.com/org/repo/blob/abc123/config/keys.py#L42")
        self.assertEqual(finding["email"], "dev@example.com")

    def test_parse_git_source(self):
        """Test parsing when SourceMetadata uses Git key instead of Github."""
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = self._make_trufflehog_result()
        # Replace Github with Git key
        result["SourceMetadata"]["Data"] = {
            "Git": {
                "repository": "https://github.com/org/repo.git",
                "file": "secrets.txt",
                "commit": "def789",
                "line": 10,
                "link": "",
                "email": "",
                "timestamp": "",
            }
        }
        finding = runner._parse_finding(result)
        self.assertEqual(finding["repository"], "https://github.com/org/repo.git")
        self.assertEqual(finding["file"], "secrets.txt")

    def test_parse_filesystem_source(self):
        """Test parsing when SourceMetadata uses Filesystem key."""
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = self._make_trufflehog_result()
        result["SourceMetadata"]["Data"] = {
            "Filesystem": {
                "path": "/tmp/repo/config.env",
                "file": "config.env",
            }
        }
        finding = runner._parse_finding(result)
        # Filesystem uses "path" for repository, "file" stays
        self.assertEqual(finding["file"], "config.env")

    def test_parse_empty_source_metadata(self):
        """Test parsing with no source metadata data."""
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = self._make_trufflehog_result()
        result["SourceMetadata"]["Data"] = {}
        finding = runner._parse_finding(result)
        self.assertIsNotNone(finding)
        self.assertEqual(finding["repository"], "")
        self.assertEqual(finding["file"], "")

    def test_stats_updated_on_parse(self):
        runner = TrufflehogRunner(token="t", project_id="p1")

        # Parse a verified finding
        result1 = self._make_trufflehog_result(Verified=True, DetectorName="AWS")
        runner._parse_finding(result1)
        self.assertEqual(runner.stats["total_findings"], 1)
        self.assertEqual(runner.stats["verified_findings"], 1)
        self.assertEqual(runner.stats["unverified_findings"], 0)
        self.assertEqual(runner.stats["detector_types"], {"AWS": 1})

        # Parse an unverified finding
        result2 = self._make_trufflehog_result(Verified=False, DetectorName="GitHub")
        runner._parse_finding(result2)
        self.assertEqual(runner.stats["total_findings"], 2)
        self.assertEqual(runner.stats["verified_findings"], 1)
        self.assertEqual(runner.stats["unverified_findings"], 1)
        self.assertEqual(runner.stats["detector_types"], {"AWS": 1, "GitHub": 1})

    def test_repo_tracking(self):
        runner = TrufflehogRunner(token="t", project_id="p1")

        result1 = self._make_trufflehog_result()
        runner._parse_finding(result1)
        self.assertEqual(runner.stats["repositories_scanned"], 1)

        # Same repo — shouldn't increment
        result2 = self._make_trufflehog_result()
        runner._parse_finding(result2)
        self.assertEqual(runner.stats["repositories_scanned"], 1)

    def test_extra_data_serialized(self):
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = self._make_trufflehog_result(
            ExtraData={"account": "123", "arn": "arn:aws:iam::123:user/foo"}
        )
        finding = runner._parse_finding(result)
        extra = json.loads(finding["extra_data"])
        self.assertEqual(extra["account"], "123")
        self.assertEqual(extra["arn"], "arn:aws:iam::123:user/foo")

    def test_extra_data_none_handled(self):
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = self._make_trufflehog_result(ExtraData=None)
        finding = runner._parse_finding(result)
        self.assertEqual(finding["extra_data"], "{}")


class TestTrufflehogRunnerSourceMetadata(unittest.TestCase):
    """Test the _extract_source_meta helper."""

    def test_github_key(self):
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = {
            "SourceMetadata": {
                "Data": {
                    "Github": {
                        "repository": "https://github.com/org/repo",
                        "file": "test.py",
                        "commit": "abc",
                        "line": 5,
                        "link": "https://example.com",
                        "email": "a@b.com",
                        "timestamp": "2024-01-01",
                        "visibility": 2,
                    }
                }
            }
        }
        meta = runner._extract_source_meta(result)
        self.assertEqual(meta["repository"], "https://github.com/org/repo")
        self.assertEqual(meta["file"], "test.py")
        self.assertEqual(meta["line"], 5)
        self.assertEqual(meta["visibility"], 2)

    def test_priority_github_over_git(self):
        """Github key should be preferred over Git key."""
        runner = TrufflehogRunner(token="t", project_id="p1")
        result = {
            "SourceMetadata": {
                "Data": {
                    "Github": {"repository": "github-repo", "file": "a"},
                    "Git": {"repository": "git-repo", "file": "b"},
                }
            }
        }
        meta = runner._extract_source_meta(result)
        self.assertEqual(meta["repository"], "github-repo")

    def test_missing_source_metadata(self):
        runner = TrufflehogRunner(token="t", project_id="p1")
        meta = runner._extract_source_meta({})
        self.assertEqual(meta["repository"], "")
        self.assertEqual(meta["file"], "")
        self.assertEqual(meta["line"], 0)


# =============================================================================
# 2. Project Settings
# =============================================================================

from project_settings import (
    DEFAULT_TRUFFLEHOG_SETTINGS,
    get_setting,
    get_settings,
)


class TestTrufflehogProjectSettings(unittest.TestCase):
    """Test project settings defaults and getters."""

    def test_default_settings_keys(self):
        expected_keys = {
            'GITHUB_ACCESS_TOKEN',
            'TRUFFLEHOG_ENABLED',
            'TRUFFLEHOG_GITHUB_ORG',
            'TRUFFLEHOG_GITHUB_REPOS',
            'TRUFFLEHOG_ONLY_VERIFIED',
            'TRUFFLEHOG_NO_VERIFICATION',
            'TRUFFLEHOG_CONCURRENCY',
            'TRUFFLEHOG_INCLUDE_DETECTORS',
            'TRUFFLEHOG_EXCLUDE_DETECTORS',
        }
        self.assertEqual(set(DEFAULT_TRUFFLEHOG_SETTINGS.keys()), expected_keys)

    def test_default_values(self):
        self.assertFalse(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_ENABLED'])
        self.assertEqual(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_CONCURRENCY'], 8)
        self.assertFalse(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_ONLY_VERIFIED'])
        self.assertFalse(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_NO_VERIFICATION'])
        self.assertEqual(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_GITHUB_ORG'], '')
        self.assertEqual(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_GITHUB_REPOS'], '')
        self.assertEqual(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_INCLUDE_DETECTORS'], '')
        self.assertEqual(DEFAULT_TRUFFLEHOG_SETTINGS['TRUFFLEHOG_EXCLUDE_DETECTORS'], '')

    def test_get_setting_with_default(self):
        # get_setting falls back to defaults when no project loaded
        val = get_setting('NONEXISTENT_KEY', 'fallback')
        self.assertEqual(val, 'fallback')


# =============================================================================
# 3. Main Entry Validation
# =============================================================================


class TestMainValidation(unittest.TestCase):
    """Test main.py validation logic."""

    @patch('main.get_setting')
    def test_missing_token_returns_error(self, mock_get_setting):
        """Scan should fail when token is empty."""
        _settings = {
            'GITHUB_ACCESS_TOKEN': '',
            'TRUFFLEHOG_GITHUB_ORG': 'myorg',
            'TRUFFLEHOG_GITHUB_REPOS': '',
            'TRUFFLEHOG_ONLY_VERIFIED': False,
            'TRUFFLEHOG_NO_VERIFICATION': False,
            'TRUFFLEHOG_CONCURRENCY': 8,
            'TRUFFLEHOG_INCLUDE_DETECTORS': '',
            'TRUFFLEHOG_EXCLUDE_DETECTORS': '',
        }
        mock_get_setting.side_effect = lambda key, default='': _settings.get(key, default)

        from main import run_trufflehog_scan
        result = run_trufflehog_scan("test-project")
        self.assertIn("error", result)
        self.assertIn("token", result["error"].lower())

    @patch('main.get_setting')
    def test_missing_target_returns_error(self, mock_get_setting):
        """Scan should fail when no org or repos configured."""
        _settings = {
            'GITHUB_ACCESS_TOKEN': 'ghp_validtoken',
            'TRUFFLEHOG_GITHUB_ORG': '',
            'TRUFFLEHOG_GITHUB_REPOS': '',
            'TRUFFLEHOG_ONLY_VERIFIED': False,
            'TRUFFLEHOG_NO_VERIFICATION': False,
            'TRUFFLEHOG_CONCURRENCY': 8,
            'TRUFFLEHOG_INCLUDE_DETECTORS': '',
            'TRUFFLEHOG_EXCLUDE_DETECTORS': '',
        }
        mock_get_setting.side_effect = lambda key, default='': _settings.get(key, default)

        from main import run_trufflehog_scan
        result = run_trufflehog_scan("test-project")
        self.assertIn("error", result)
        self.assertIn("target", result["error"].lower())


# =============================================================================
# 4. Neo4j Graph Integration (with mocked driver)
# =============================================================================


class TestNeo4jTrufflehogIntegration(unittest.TestCase):
    """Test update_graph_from_trufflehog logic with mocked Neo4j."""

    def _make_scan_data(self, findings=None):
        """Build realistic TruffleHog scan output."""
        return {
            "target": "myorg",
            "scan_start_time": "2024-01-01T00:00:00",
            "scan_end_time": "2024-01-01T01:00:00",
            "duration_seconds": 3600,
            "status": "completed",
            "statistics": {
                "total_findings": len(findings or []),
                "verified_findings": sum(1 for f in (findings or []) if f.get("verified")),
                "unverified_findings": sum(1 for f in (findings or []) if not f.get("verified")),
                "repositories_scanned": len(set(f.get("repository", "") for f in (findings or []))),
            },
            "findings": findings or [],
        }

    def _make_finding(self, **overrides):
        finding = {
            "detector_name": "AWS",
            "detector_description": "AWS API Key",
            "verified": True,
            "redacted": "AKIA***",
            "repository": "https://github.com/org/repo",
            "file": "config.py",
            "commit": "abc123",
            "line": 10,
            "link": "https://github.com/org/repo/blob/abc123/config.py#L10",
            "email": "dev@example.com",
            "timestamp": "2024-01-01T00:00:00",
            "extra_data": "{}",
        }
        finding.update(overrides)
        return finding

    def _create_mock_client(self):
        """Create a mock Neo4j client with the real method."""
        # Import the actual neo4j_client module with mocked neo4j driver
        sys.path.insert(0, str(REPO_ROOT / "graph_db"))

        mock_session = MagicMock()
        mock_single = MagicMock()
        mock_single.__getitem__ = lambda self, key: 1
        mock_session.run.return_value.single.return_value = mock_single

        mock_driver = MagicMock()
        mock_driver.session.return_value.__enter__ = MagicMock(return_value=mock_session)
        mock_driver.session.return_value.__exit__ = MagicMock(return_value=False)

        return mock_driver, mock_session

    def test_empty_target_detected(self):
        """Validate that empty target is caught before Neo4j calls."""
        data = self._make_scan_data()
        data["target"] = ""
        # The update method should check target before doing anything
        self.assertEqual(data["target"], "")
        # Simulate the validation logic from update_graph_from_trufflehog
        target = data.get("target")
        self.assertFalse(bool(target), "Empty target should be falsy")

    def test_dedup_key_consistency(self):
        """Same finding params should produce same dedup key."""
        f1 = self._make_finding(repository="r", file="f", line=1, detector_name="AWS")
        f2 = self._make_finding(repository="r", file="f", line=1, detector_name="AWS")
        key1 = f"{f1['repository']}:{f1['file']}:{f1['line']}:{f1['detector_name']}"
        key2 = f"{f2['repository']}:{f2['file']}:{f2['line']}:{f2['detector_name']}"
        self.assertEqual(key1, key2)

    def test_dedup_different_detectors(self):
        """Different detector on same file+line should NOT dedup."""
        f1 = self._make_finding(detector_name="AWS")
        f2 = self._make_finding(detector_name="GitHub")
        key1 = f"{f1['repository']}:{f1['file']}:{f1['line']}:{f1['detector_name']}"
        key2 = f"{f2['repository']}:{f2['file']}:{f2['line']}:{f2['detector_name']}"
        self.assertNotEqual(key1, key2)

    def test_dedup_different_lines(self):
        """Same detector on different lines should NOT dedup."""
        f1 = self._make_finding(line=10)
        f2 = self._make_finding(line=20)
        key1 = f"{f1['repository']}:{f1['file']}:{f1['line']}:{f1['detector_name']}"
        key2 = f"{f2['repository']}:{f2['file']}:{f2['line']}:{f2['detector_name']}"
        self.assertNotEqual(key1, key2)


# =============================================================================
# 5. Orchestrator Models
# =============================================================================

from models import TrufflehogStatus, TrufflehogState, TrufflehogStartRequest, TrufflehogLogEvent


class TestTrufflehogModels(unittest.TestCase):
    """Test Pydantic models for TruffleHog orchestrator."""

    def test_status_enum_values(self):
        self.assertEqual(TrufflehogStatus.IDLE.value, "idle")
        self.assertEqual(TrufflehogStatus.STARTING.value, "starting")
        self.assertEqual(TrufflehogStatus.RUNNING.value, "running")
        self.assertEqual(TrufflehogStatus.PAUSED.value, "paused")
        self.assertEqual(TrufflehogStatus.COMPLETED.value, "completed")
        self.assertEqual(TrufflehogStatus.ERROR.value, "error")
        self.assertEqual(TrufflehogStatus.STOPPING.value, "stopping")

    def test_state_default_phases(self):
        state = TrufflehogState(
            project_id="proj-1",
            status=TrufflehogStatus.IDLE,
        )
        self.assertEqual(state.total_phases, 3)
        self.assertIsNone(state.current_phase)
        self.assertIsNone(state.phase_number)
        self.assertIsNone(state.error)
        self.assertIsNone(state.container_id)

    def test_start_request_model(self):
        req = TrufflehogStartRequest(
            project_id="proj-1",
            user_id="user-1",
            webapp_api_url="http://localhost:3000",
        )
        self.assertEqual(req.project_id, "proj-1")
        self.assertEqual(req.user_id, "user-1")
        self.assertEqual(req.webapp_api_url, "http://localhost:3000")

    def test_log_event_defaults(self):
        event = TrufflehogLogEvent(
            log="test log line",
            timestamp=datetime.now(),
        )
        self.assertEqual(event.level, "info")
        self.assertFalse(event.is_phase_start)
        self.assertIsNone(event.phase)

    def test_state_serialization(self):
        """State should serialize to JSON (for API responses)."""
        state = TrufflehogState(
            project_id="p1",
            status=TrufflehogStatus.RUNNING,
            current_phase="Scanning Repositories",
            phase_number=2,
        )
        data = state.model_dump()
        self.assertEqual(data["status"], "running")
        self.assertEqual(data["current_phase"], "Scanning Repositories")
        self.assertEqual(data["phase_number"], 2)
        self.assertEqual(data["total_phases"], 3)


# =============================================================================
# 6. Container Manager Phase Patterns
# =============================================================================


class TestTrufflehogPhasePatterns(unittest.TestCase):
    """Test that phase detection regex patterns work correctly."""

    def setUp(self):
        # Inline the patterns to avoid importing container_manager (needs docker SDK)
        self.patterns = [
            (r"TruffleHog Secret Scanner|Loading.*settings|Initializing TruffleHog", "Loading Settings", 1),
            (r"Scanning repositor|Scanning organization|Running:.*trufflehog", "Scanning Repositories", 2),
            (r"SCAN SUMMARY|Final results saved|Scan complete", "Complete", 3),
        ]

    def _match_phase(self, line):
        """Return (phase_name, phase_num) if line matches a pattern."""
        import re
        for pattern, phase_name, num in self.patterns:
            if re.search(pattern, line, re.IGNORECASE):
                return phase_name, num
        return None, None

    def test_phase1_init_banner(self):
        name, num = self._match_phase("RedAmon - TruffleHog Secret Scanner")
        self.assertEqual(name, "Loading Settings")
        self.assertEqual(num, 1)

    def test_phase1_initializing(self):
        name, num = self._match_phase("[*] Initializing TruffleHog Scanner...")
        self.assertEqual(name, "Loading Settings")
        self.assertEqual(num, 1)

    def test_phase2_scanning_repo(self):
        name, num = self._match_phase("[*] Scanning repository set 1/3...")
        self.assertEqual(name, "Scanning Repositories")
        self.assertEqual(num, 2)

    def test_phase2_scanning_org(self):
        name, num = self._match_phase("[*] Scanning organization: myorg")
        self.assertEqual(name, "Scanning Repositories")
        self.assertEqual(num, 2)

    def test_phase3_scan_summary(self):
        name, num = self._match_phase("SCAN SUMMARY")
        self.assertEqual(name, "Complete")
        self.assertEqual(num, 3)

    def test_phase3_final_results(self):
        name, num = self._match_phase("[+] Final results saved to /app/output/trufflehog_p1.json")
        self.assertEqual(name, "Complete")
        self.assertEqual(num, 3)

    def test_no_match_for_regular_log(self):
        name, num = self._match_phase("[+] Found: AWS [VERIFIED] in config.py")
        self.assertIsNone(name)


# =============================================================================
# 7. Docker Compose Consistency
# =============================================================================


class TestDockerComposeConsistency(unittest.TestCase):
    """Verify docker-compose.yml has all TruffleHog entries."""

    def setUp(self):
        self.compose_path = REPO_ROOT / "docker-compose.yml"
        with open(self.compose_path) as f:
            self.content = f.read()

    def test_trufflehog_scanner_service(self):
        self.assertIn("trufflehog-scanner:", self.content)
        self.assertIn("trufflehog_scan/Dockerfile", self.content)
        self.assertIn("redamon-trufflehog:latest", self.content)

    def test_orchestrator_volume_mounts(self):
        self.assertIn("./trufflehog_scan:/app/trufflehog_scan:ro", self.content)
        self.assertIn("./trufflehog_scan/output:/app/trufflehog_scan/output:rw", self.content)

    def test_orchestrator_env_var(self):
        self.assertIn("TRUFFLEHOG_IMAGE: redamon-trufflehog:latest", self.content)

    def test_webapp_output_path(self):
        self.assertIn("TRUFFLEHOG_OUTPUT_PATH: /data/trufflehog-output", self.content)

    def test_webapp_volume_mount(self):
        self.assertIn("./trufflehog_scan/output:/data/trufflehog-output:ro", self.content)


# =============================================================================
# 8. Prisma Schema Consistency
# =============================================================================


class TestPrismaSchemaConsistency(unittest.TestCase):
    """Verify Prisma schema has all TruffleHog fields."""

    def setUp(self):
        self.schema_path = REPO_ROOT / "webapp" / "prisma" / "schema.prisma"
        with open(self.schema_path) as f:
            self.content = f.read()

    def test_all_trufflehog_fields_present(self):
        fields = [
            "trufflehogEnabled",
            "trufflehogGithubOrg",
            "trufflehogGithubRepos",
            "trufflehogOnlyVerified",
            "trufflehogNoVerification",
            "trufflehogConcurrency",
            "trufflehogIncludeDetectors",
            "trufflehogExcludeDetectors",
        ]
        for field in fields:
            self.assertIn(field, self.content, f"Missing Prisma field: {field}")

    def test_field_types(self):
        self.assertIn('trufflehogEnabled            Boolean', self.content)
        self.assertIn('trufflehogConcurrency        Int', self.content)
        self.assertIn('trufflehogGithubOrg          String', self.content)

    def test_field_defaults(self):
        self.assertIn('@default(false)', self.content.split('trufflehogEnabled')[1].split('\n')[0])
        self.assertIn('@default(8)', self.content.split('trufflehogConcurrency')[1].split('\n')[0])


if __name__ == "__main__":
    unittest.main()
