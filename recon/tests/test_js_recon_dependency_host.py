"""R-49: a dependency-confusion finding keeps the host of the file that imports it.

detect_dependency_confusion emits ``source_urls`` (every JS file that imports the
package, at most five), while the writer read ``source_url`` / ``js_url``. Each
finding was stored with no ``source_url``, ``base_url: 'upload'`` (as if it came
from an uploaded file) and no parent JS file, so the Priority Board could not
place it on a host and a host-scoped keep never matched it.

The producer runs for real here; only the npm registry lookup is mocked.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from graph_db.mixins.base_mixin import keep_host_patterns  # noqa: E402
from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402
from recon.helpers.js_recon import dependency  # noqa: E402

APP_JS = "https://app.example.com/static/js/main.js"
ADMIN_JS = "https://admin.example.com/assets/admin.js"
IMPORT = "import { Button } from '@acme/internal-ui';\n"


def _dependencies(js_files, **settings):
    """The real producer, with every package missing from the public registry."""
    with mock.patch.object(dependency, "_check_npm_registry", return_value=False):
        return dependency.detect_dependency_confusion(
            js_files, {"JS_RECON_DEPENDENCY_CHECK": True, **settings})


class _Result:
    def __init__(self, record):
        self.record = record

    def single(self):
        return self.record


class _Session:
    """Answers a BaseURL link by whether that BaseURL exists."""

    def __init__(self, baseurls=(), domains=()):
        self.baseurls, self.domains = set(baseurls), set(domains)
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "HAS_JS_FILE" in query:
            if "BaseURL" in query:
                return _Result({"linked": int(kwargs.get("base_url") in self.baseurls)})
            if "Domain" in query:
                return _Result({"linked": int(kwargs.get("dname") in self.domains)})
            return _Result({"linked": 0})
        return _Result({"linked": 1})


class _Writer(JsReconMixin):
    def __init__(self, session):
        self.driver = mock.MagicMock()
        self.driver.session.return_value = session


def _write(dependencies, session):
    recon_data = {
        "domain": "example.com",
        "subdomains": ["app.example.com", "admin.example.com"],
        "js_recon": {
            "scan_metadata": {"scan_timestamp": "2026-11-11T00:00:00Z"},
            "dependencies": dependencies,
        },
    }
    return _Writer(session).update_graph_from_js_recon(recon_data, "u1", "p1")


def _nodes(session, finding_type):
    return [kw["props"] for q, kw in session.calls
            if "MERGE (jf:JsReconFinding" in q and kw["props"]["finding_type"] == finding_type]


def test_the_producer_names_its_files_in_source_urls():
    [finding] = _dependencies([{"url": APP_JS, "content": IMPORT}])
    assert finding["package_name"] == "@acme/internal-ui"
    assert finding["source_urls"] == [APP_JS]
    assert "source_url" not in finding


def test_the_finding_takes_the_host_of_the_file_that_imports_it():
    session = _Session(baseurls={"https://app.example.com"})
    _write(_dependencies([{"url": APP_JS, "content": IMPORT}]), session)

    [props] = _nodes(session, "dependency_confusion")
    assert props["base_url"] == "https://app.example.com"
    assert props["source_url"] == APP_JS
    assert props["source_urls"] == [APP_JS]
    assert props["package_name"] == "@acme/internal-ui"


def test_the_finding_hangs_off_its_file_node_under_the_baseurl():
    session = _Session(baseurls={"https://app.example.com"})
    stats = _write(_dependencies([{"url": APP_JS, "content": IMPORT}]), session)

    [file_props] = _nodes(session, "js_file")
    assert file_props["source_url"] == APP_JS
    assert file_props["is_uploaded"] is False
    [(query, link)] = [(q, k) for q, k in session.calls if "HAS_JS_FILE" in q]
    assert "MATCH (bu:BaseURL {url: $base_url, user_id: $uid, project_id: $pid})" in query
    assert (link["base_url"], link["fid"]) == ("https://app.example.com", file_props["id"])

    [finding] = _nodes(session, "dependency_confusion")
    [(_, child)] = [(q, k) for q, k in session.calls if "HAS_JS_FINDING" in q]
    assert (child["fid"], child["nid"]) == (file_props["id"], finding["id"])
    # file -> BaseURL, file -> finding
    assert stats["relationships_created"] == 2


def test_a_package_on_two_hosts_keeps_both_and_one_stable_parent():
    """The download order is not stable (as_completed), so neither is the
    producer's list: sorted, the host and the stored list do not move between
    two runs that saw the same files."""
    files = [{"url": APP_JS, "content": IMPORT}, {"url": ADMIN_JS, "content": IMPORT}]
    for order in (files, files[::-1]):
        session = _Session(baseurls={"https://app.example.com", "https://admin.example.com"})
        _write(_dependencies(order), session)

        [props] = _nodes(session, "dependency_confusion")
        assert props["source_urls"] == [ADMIN_JS, APP_JS]
        assert props["source_url"] == ADMIN_JS
        assert props["base_url"] == "https://admin.example.com"
        # One parent: a second HAS_JS_FINDING would list the finding twice in
        # every reader that walks BaseURL -> file -> finding.
        assert [f["source_url"] for f in _nodes(session, "js_file")] == [ADMIN_JS]
        assert len([1 for q, _ in session.calls if "HAS_JS_FINDING" in q]) == 1


def test_a_package_named_only_in_the_internal_list_gets_no_file_node(tmp_path):
    packages = tmp_path / "internal.txt"
    packages.write_text("@acme/billing-core\n")
    session = _Session(domains={"example.com"})
    _write(_dependencies([], JS_RECON_CUSTOM_PACKAGES=str(packages)), session)

    [props] = _nodes(session, "dependency_confusion")
    assert props["source_urls"] == ["custom_packages_file"]
    assert props["source_url"] == ""
    assert props["base_url"] == "upload"
    assert _nodes(session, "js_file") == []


def test_an_uploaded_file_stays_an_upload():
    session = _Session(domains={"example.com"})
    _write(_dependencies([{"url": "upload://bundle.js", "content": IMPORT}]), session)

    [props] = _nodes(session, "dependency_confusion")
    assert (props["source_url"], props["base_url"]) == ("upload://bundle.js", "upload")
    [file_props] = _nodes(session, "js_file")
    assert file_props["is_uploaded"] is True


def test_a_finding_in_the_older_single_url_shape_still_resolves():
    session = _Session(baseurls={"https://app.example.com"})
    _write([{"id": "d1", "finding_type": "dependency_confusion", "package_name": "@acme/ui",
             "severity": "critical", "source_url": APP_JS}], session)

    [props] = _nodes(session, "dependency_confusion")
    assert (props["source_url"], props["base_url"]) == (APP_JS, "https://app.example.com")
    assert props["source_urls"] == [APP_JS]


def test_a_host_js_recon_could_not_recheck_keeps_the_finding():
    """The prune's keep_hosts regexes run with Cypher's `=~` (a whole-value
    match) against _KEEP_HOST_FIELDS, base_url and source_url among them.
    With base_url 'upload' no host ever matched, so a capped run pruned a
    finding it never re-checked."""
    session = _Session(baseurls={"https://app.example.com"})
    _write(_dependencies([{"url": APP_JS, "content": IMPORT}]), session)
    [props] = _nodes(session, "dependency_confusion")

    def kept(host):
        return any(re.fullmatch(rx, props[field])
                   for rx in keep_host_patterns([host]) for field in ("base_url", "source_url"))

    assert kept("app.example.com")
    assert not kept("admin.example.com")
