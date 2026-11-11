"""
L-16: no layer ships a domain-ownership token every install shares.

The ownership check passes when `<prefix>.<domain>` publishes
`redamon-verify=<token>`. A default token is printed in the source, so a record
published for one project with it verifies every other project on the install
that kept it. Each project gets its own random token when it is created
(Prisma `@default(uuid())`, and the create paths replace a blank or legacy
value), so the pipeline has no default to fall back on.

Run: python -m pytest tests/test_ownership_token_default.py -v
"""
from __future__ import annotations

import json
import os
from unittest.mock import patch

from recon import settings_registry as reg
from recon.project_settings import DEFAULT_SETTINGS, fetch_project_settings

LEGACY_TOKEN = "your-secret-token-here"
REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        return None

    def json(self):
        return self._payload


def _fetch(project: dict) -> dict:
    payload = {"userId": "u1", "targetDomain": "example.com", **project}
    with patch("requests.get", return_value=_Resp(payload)):
        return fetch_project_settings("p1", "http://webapp.invalid")


def test_the_pipeline_has_no_default_token():
    assert DEFAULT_SETTINGS["OWNERSHIP_TOKEN"] == ""


def test_the_registry_default_is_generated_per_project():
    """Prisma owns the default; a function default has no literal value."""
    spec = reg.field("ownershipToken")
    assert spec["has_default"] is True
    assert spec["default"] is None


def test_no_generated_registry_artifact_carries_the_legacy_token():
    for rel in ("recon_settings/registry.json", "webapp/src/lib/reconSettings/registry.json"):
        path = os.path.join(REPO, rel)
        if os.path.exists(path):
            with open(path, encoding="utf-8") as fh:
                assert LEGACY_TOKEN not in fh.read(), rel


def test_a_project_token_reaches_the_pipeline_unchanged():
    token = "0b8f6c1e-3d2a-4c55-9a77-1f0e2d3c4b5a"
    settings = _fetch({"verifyDomainOwnership": True, "ownershipToken": token})
    assert settings["VERIFY_DOMAIN_OWNERSHIP"] is True
    assert settings["OWNERSHIP_TOKEN"] == token


def test_the_schema_default_is_not_a_literal():
    schema = os.path.join(REPO, "webapp", "prisma", "schema.prisma")
    if not os.path.exists(schema):
        return
    with open(schema, encoding="utf-8") as fh:
        line = next(l for l in fh if l.strip().startswith("ownershipToken "))
    assert "@default(uuid())" in line, line
    assert json.dumps(LEGACY_TOKEN) not in line
