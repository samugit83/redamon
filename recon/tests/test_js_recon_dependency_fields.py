"""S-19: a dependency-confusion finding stores its scope, npm answer and recommendation.

detect_dependency_confusion produces ``scope``, ``npm_exists`` and
``recommendation`` on every finding, but the writer dropped all three. The JS
Recon Dependencies table then read "On npm? No" on every row, a package that IS
published (the ``depconf-exists`` finding) included, and an empty Scope.

The producer runs for real here; only the npm registry lookup is mocked. The
stored node is checked against a real database in
tests/test_js_recon_dependency_fields_graph_live.py.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402
from recon.helpers.js_recon import dependency  # noqa: E402

APP_JS = "https://app.example.com/static/js/main.js"
IMPORTS = "import a from '@acme/internal-ui';\nimport b from '@acme/billing-core';\n"


class _Result:
    def single(self):
        return {"linked": 1}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return _Result()


class _Writer(JsReconMixin):
    def __init__(self, session):
        self.driver = mock.MagicMock()
        self.driver.session.return_value = session


def _produce(tmp_path, published):
    """The real producer: ``published`` packages answer 200 on npm, the rest 404.
    Both are on the project's internal-package list, so a published one is
    reported too (the ``depconf-exists`` finding)."""
    internal = tmp_path / "internal.txt"
    internal.write_text("@acme/internal-ui\n@acme/billing-core\n")
    dependency._npm_cache.clear()
    with mock.patch.object(dependency, "_check_npm_registry", side_effect=lambda name, *a, **k: name in published):
        return dependency.detect_dependency_confusion(
            [{"url": APP_JS, "content": IMPORTS}],
            {"JS_RECON_DEPENDENCY_CHECK": True, "JS_RECON_CUSTOM_PACKAGES": str(internal)})


def _stored(findings):
    session = _Session()
    _Writer(session).update_graph_from_js_recon({
        "domain": "example.com",
        "subdomains": ["app.example.com"],
        "js_recon": {"scan_metadata": {"scan_timestamp": "2026-11-11T00:00:00Z"},
                     "dependencies": findings},
    }, "u1", "p1")
    return {kw["props"]["package_name"]: kw["props"] for q, kw in session.calls
            if "MERGE (jf:JsReconFinding" in q and kw["props"]["finding_type"] == "dependency_confusion"}


def test_the_producer_reports_scope_npm_answer_and_recommendation(tmp_path):
    by_name = {f["package_name"]: f for f in _produce(tmp_path, published={"@acme/billing-core"})}
    assert by_name["@acme/internal-ui"]["npm_exists"] is False
    assert by_name["@acme/billing-core"]["npm_exists"] is True
    assert {f["scope"] for f in by_name.values()} == {"@acme"}
    assert all(f["recommendation"] for f in by_name.values())


def test_an_unpublished_package_is_stored_as_not_on_npm(tmp_path):
    props = _stored(_produce(tmp_path, published=set()))["@acme/internal-ui"]
    assert props["npm_exists"] is False
    assert props["package_scope"] == "@acme"
    assert props["recommendation"] == "Register @acme/internal-ui on npm as a placeholder or use a private registry."


def test_a_published_internal_package_is_stored_as_on_npm(tmp_path):
    """The row the table showed as "No" although the finding says it IS on npm."""
    props = _stored(_produce(tmp_path, published={"@acme/billing-core"}))["@acme/billing-core"]
    assert props["npm_exists"] is True
    assert props["severity"] == "high"
    assert props["package_scope"] == "@acme"
    assert props["recommendation"] == "Verify npm ownership of @acme/billing-core."


def test_a_finding_without_an_npm_answer_stores_none_not_false():
    """No answer is "not known", never "not published": None makes
    ``SET jf += $props`` leave the property absent, which readers show as
    unknown."""
    props = _stored([{"id": "d1", "finding_type": "dependency_confusion", "package_name": "@acme/ui",
                      "severity": "critical", "source_urls": [APP_JS]}])["@acme/ui"]
    assert props["npm_exists"] is None
    assert props["recommendation"] is None
    # The producer's rule (the part before the slash), for a finding that
    # predates the field.
    assert props["package_scope"] == "@acme"


def test_an_unscoped_internal_package_has_no_scope():
    props = _stored([{"id": "d2", "finding_type": "dependency_confusion", "package_name": "billing-core",
                      "scope": "", "npm_exists": False, "source_urls": ["custom_packages_file"]}])["billing-core"]
    assert props["package_scope"] is None
    assert props["npm_exists"] is False


def test_a_non_boolean_npm_answer_is_not_coerced():
    props = _stored([{"id": "d3", "finding_type": "dependency_confusion", "package_name": "@acme/x",
                      "scope": "@acme", "npm_exists": "false", "source_urls": [APP_JS]}])["@acme/x"]
    assert props["npm_exists"] is None


def test_other_finding_kinds_get_no_dependency_fields():
    session = _Session()
    _Writer(session).update_graph_from_js_recon({
        "domain": "example.com", "subdomains": ["app.example.com"],
        "js_recon": {"scan_metadata": {}, "dom_sinks": [
            {"id": "s1", "finding_type": "dom_sink", "source_url": APP_JS, "line": 3}]},
    }, "u1", "p1")
    [props] = [kw["props"] for q, kw in session.calls
               if "MERGE (jf:JsReconFinding" in q and kw["props"]["finding_type"] == "dom_sink"]
    assert not {"package_scope", "npm_exists", "recommendation"} & set(props)
