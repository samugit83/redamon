"""V3 — tool Docker image injection.

Recon modules pass ``*_DOCKER_IMAGE`` verbatim to ``docker run`` on the host Docker
daemon (often ``--net=host``), so an image a caller could choose would be arbitrary
container execution on the host. No image is a project setting: the loader never
reads one from the project row, and ``sanitize_image_settings`` (called at the
``fetch_project_settings`` chokepoint) pins every key to its own shipped default.

Exploit reproduction (``test_fetch_*``): an image under any ``*DockerImage`` key of
the project row the webapp returns (an old export, a stale client) must NOT
survive into the loaded settings.

Run: cd recon && python -m pytest tests/test_image_allowlist.py -q
"""
import os
import sys

import requests

RECON_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))  # .../recon
APP_DIR = os.path.dirname(RECON_DIR)                                     # .../  (recon's parent)
# Need both: APP_DIR so the module's `from recon.helpers...` absolute imports
# resolve, and RECON_DIR so `import project_settings` resolves.
for _p in (APP_DIR, RECON_DIR):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import project_settings as ps  # noqa: E402

EVIL = "attacker/evil:latest"
SAFE_NAABU = "projectdiscovery/naabu:latest"


# --------------------------------------------------------------------------
# Unit — the sanitizer itself
# --------------------------------------------------------------------------

def test_malicious_image_pinned_to_default():
    s = {"NAABU_DOCKER_IMAGE": EVIL}
    ps.sanitize_image_settings(s)
    assert s["NAABU_DOCKER_IMAGE"] == SAFE_NAABU
    assert "attacker" not in s["NAABU_DOCKER_IMAGE"]


def test_shipped_image_is_kept():
    s = {"HTTPX_DOCKER_IMAGE": "projectdiscovery/httpx:latest"}
    ps.sanitize_image_settings(s)
    assert s["HTTPX_DOCKER_IMAGE"] == "projectdiscovery/httpx:latest"


def test_unknown_image_key_is_dropped():
    # Unknown key -> no shipped default -> drop so the consumer uses its own.
    s = {"EVILTOOL_DOCKER_IMAGE": EVIL}
    ps.sanitize_image_settings(s)
    assert "EVILTOOL_DOCKER_IMAGE" not in s


def test_registry_and_digest_variants_blocked():
    for evil in (
        "ghcr.io/attacker/evil:latest",
        "attacker/evil@sha256:" + "d" * 64,
        "localhost:5000/evil:latest",
        "projectdiscovery/naabu:latest; rm -rf /",  # not a real arg vector, but must be rejected
    ):
        s = {"KATANA_DOCKER_IMAGE": evil}
        ps.sanitize_image_settings(s)
        assert s["KATANA_DOCKER_IMAGE"] == ps.DEFAULT_SETTINGS["KATANA_DOCKER_IMAGE"]


def test_all_shipped_defaults_pass_unchanged():
    # Every shipped default must be allowlisted, else real scans would break.
    s = {k: v for k, v in ps.DEFAULT_SETTINGS.items() if k.endswith("_DOCKER_IMAGE")}
    before = dict(s)
    ps.sanitize_image_settings(s)
    assert s == before


def test_non_image_settings_untouched():
    s = {"NAABU_RATE_LIMIT": 1000, "TARGET_DOMAIN": "example.com"}
    before = dict(s)
    ps.sanitize_image_settings(s)
    assert s == before


def test_allowlist_is_nonempty_and_has_naabu():
    assert SAFE_NAABU in ps.ALLOWED_TOOL_IMAGES
    assert len(ps.ALLOWED_TOOL_IMAGES) >= 10


# --------------------------------------------------------------------------
# Fixed, not merely allowlisted
# --------------------------------------------------------------------------

def test_another_tools_shipped_image_is_pinned():
    # Shipped is not enough: the naabu key must carry the naabu image.
    s = {"NAABU_DOCKER_IMAGE": "projectdiscovery/nuclei:latest"}
    ps.sanitize_image_settings(s)
    assert s["NAABU_DOCKER_IMAGE"] == SAFE_NAABU


def test_the_old_operator_env_widens_nothing(monkeypatch):
    # RECON_EXTRA_ALLOWED_IMAGES used to admit private-registry mirrors. Images
    # are fixed now, so a mirror is pinned like any other non-shipped value.
    mirror = "myregistry.local/projectdiscovery/naabu:latest"
    monkeypatch.setenv("RECON_EXTRA_ALLOWED_IMAGES", mirror)
    s = {"NAABU_DOCKER_IMAGE": mirror}
    ps.sanitize_image_settings(s)
    assert s["NAABU_DOCKER_IMAGE"] == SAFE_NAABU


# --------------------------------------------------------------------------
# Integration — settings -> consumer -> the actual `docker run` argv
# --------------------------------------------------------------------------

def test_integration_naabu_docker_argv_uses_sanitized_image(monkeypatch):
    """End-to-end: a malicious image is sanitized at the chokepoint, then the
    real port_scan command-builder produces a `docker run` argv with the SAFE
    image — proving the consumer never sees the attacker value."""
    from main_recon_modules.port_scan import build_naabu_command  # noqa: E402

    settings = {"NAABU_DOCKER_IMAGE": EVIL}
    ps.sanitize_image_settings(settings)  # the chokepoint
    # /tmp/redamon paths are passed through get_host_path unchanged (no env dep).
    cmd = build_naabu_command("/tmp/redamon/targets.txt", "/tmp/redamon/out.json", settings)

    assert "docker" in cmd and "run" in cmd
    assert SAFE_NAABU in cmd
    assert EVIL not in cmd
    assert not any("attacker" in str(tok) for tok in cmd)


# --------------------------------------------------------------------------
# Exploit reproduction — the chokepoint (fetch_project_settings)
# --------------------------------------------------------------------------

class _Resp:
    status_code = 200

    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _install_fake_webapp(monkeypatch, project):
    # fetch_project_settings makes >1 requests.get (project + user settings).
    # Return the project for the project URL, an empty dict for everything else.
    def fake_get(url, *a, **k):
        if "/api/projects/" in url:
            return _Resp(project)
        return _Resp({})
    monkeypatch.setattr(requests, "get", fake_get)


def test_fetch_sanitizes_malicious_image(monkeypatch):
    project = {"userId": "u1", "targetDomain": "example.com", "naabuDockerImage": EVIL}
    _install_fake_webapp(monkeypatch, project)
    settings = ps.fetch_project_settings("p1", "http://webapp:3000")
    # PRE-PATCH this is EVIL (the orchestrator would `docker run attacker/evil`).
    assert settings["NAABU_DOCKER_IMAGE"] == SAFE_NAABU
    assert "attacker" not in settings["NAABU_DOCKER_IMAGE"]


def test_fetch_ignores_every_image_column_on_the_row(monkeypatch):
    image_keys = [k for k in ps.DEFAULT_SETTINGS if k.endswith("_DOCKER_IMAGE")]
    camel = {k: k.lower().split("_")[0] + "".join(w.capitalize() for w in k.lower().split("_")[1:])
             for k in image_keys}
    project = {"userId": "u1", "targetDomain": "example.com", **{c: EVIL for c in camel.values()}}
    _install_fake_webapp(monkeypatch, project)
    settings = ps.fetch_project_settings("p1", "http://webapp:3000")
    assert {k: settings[k] for k in image_keys} == {k: ps.DEFAULT_SETTINGS[k] for k in image_keys}


def test_fetch_keeps_legit_default_image(monkeypatch):
    project = {"userId": "u1", "targetDomain": "example.com"}  # no override
    _install_fake_webapp(monkeypatch, project)
    settings = ps.fetch_project_settings("p1", "http://webapp:3000")
    assert settings["NAABU_DOCKER_IMAGE"] == SAFE_NAABU
