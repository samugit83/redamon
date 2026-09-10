#!/usr/bin/env python3
"""I4 - github-hunt must not print harvested secret values to stdout.

_add_finding writes to the operator log stream (docker logs), so the cleartext
value of a discovered secret must never appear there. The on-disk JSON artifact
still carries it (tracker decision), which is what separates redaction from
dropping the finding.

PyGithub is stubbed so the module's import guard passes on a bare host, and the
hunter is built via __new__ so nothing touches the network.
"""
import io
import os
import sys
import types
import unittest.mock as mock
from contextlib import redirect_stdout

import pytest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
SCANNER_DIR = os.path.join(REPO_ROOT, "scanners", "github_secret_hunt")

SECRET = "AKIAIOSFODNN7EXAMPLE_supersecret"

# The value-bearing detail keys github_secret_hunt redacts. Kept here as the
# contract under test: a key dropped from the scanner's set must fail here.
SENSITIVE_KEYS = ("sample", "value", "secret", "match", "matched",
                  "raw", "token", "entropy_value", "high_entropy_value")


@pytest.fixture(scope="module")
def ghh():
    """Import the scanner with PyGithub stubbed, without leaving the stub or the
    path entry behind for whatever runs next (conftest ISOLATION RULE)."""
    stub = types.ModuleType("github")
    stub.Github = object
    stub.Auth = types.SimpleNamespace(Token=lambda *a, **k: None)
    exc = types.ModuleType("github.GithubException")
    exc.RateLimitExceededException = type("RateLimitExceededException", (Exception,), {})
    exc.GithubException = type("GithubException", (Exception,), {})
    stub.GithubException = exc

    with mock.patch.dict(sys.modules, {"github": stub, "github.GithubException": exc}), \
            mock.patch.object(sys, "path", [SCANNER_DIR] + sys.path):
        import github_secret_hunt

        yield github_secret_hunt


def emit(ghh, details, finding_type="SECRET"):
    """Drive _add_finding on a network-free hunter. Returns (stdout, finding)."""
    hunter = ghh.GitHubSecretHunter.__new__(ghh.GitHubSecretHunter)
    hunter.findings = []
    hunter.stats = {"secrets_found": 0, "sensitive_files": 0, "high_entropy": 0}
    hunter._save_incremental = lambda: None

    buf = io.StringIO()
    with redirect_stdout(buf):
        hunter._add_finding(finding_type, "victim/repo", "config/.env",
                            "aws_access_key", details)
    return buf.getvalue(), hunter.findings[0]


@pytest.fixture(scope="module")
def emitted(ghh):
    return emit(ghh, {"sample": SECRET, "value": SECRET, "line": 42})


def test_banner_is_printed(emitted):
    out, _ = emitted
    assert "SECRET FOUND: aws_access_key" in out


def test_repository_metadata_is_printed(emitted):
    out, _ = emitted
    assert "victim/repo" in out


def test_non_sensitive_detail_is_printed(emitted):
    out, _ = emitted
    assert "line: 42" in out


def test_secret_value_never_reaches_stdout(emitted):
    out, _ = emitted
    assert SECRET not in out


def test_sensitive_field_is_marked_redacted(emitted):
    out, _ = emitted
    assert "[REDACTED]" in out


def test_finding_dict_retains_the_value(emitted):
    """The on-disk artifact is deliberately unchanged; only stdout is redacted."""
    _, finding = emitted
    assert finding["details"]["sample"] == SECRET


@pytest.mark.parametrize("key", SENSITIVE_KEYS)
def test_every_sensitive_key_is_redacted(ghh, key):
    out, finding = emit(ghh, {key: SECRET, "line": 42})
    assert SECRET not in out
    assert f"{key}: [REDACTED]" in out
    assert finding["details"][key] == SECRET
