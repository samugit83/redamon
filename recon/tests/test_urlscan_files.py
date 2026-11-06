"""Item 3: sensitive files and documents in the URLs urlscan already returned,
and their hand-over to Route Exposure.

classify_file matches the path's last part, never the host; Route Exposure gets
only the kinds a signature proves, each requested the way it needs (a heap dump
with HEAD, a dump as a backup read, .git as its HEAD and config), on bases that
are live in this scan. Hosts are example.test; nothing here is requested.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.url_leaks import classify_file  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402
from recon.route_exposure import harvest as h  # noqa: E402

B = "https://files.example.test"


class TestClassifyFile:
    @pytest.mark.parametrize("path,kind", [
        ("/.env", "env"), ("/.env.production", "env"), ("/.git/config", "vcs"), ("/x/.svn/entries", "vcs"),
        ("/.git", "vcs"), ("/k.key", "private_key"), ("/id_rsa", "private_key"), ("/dump.sql.gz", "db_dump"),
        ("/db.sqlite3", "db_dump"), ("/index.php.bak", "backup"), ("/x~", "backup"), ("/backup.zip", "backup"),
        ("/www.tar.gz", "backup"), ("/debug.log", "log"), ("/error_log", "log"), ("/web.config", "config"),
        ("/appsettings.Production.json", "config"), ("/phpinfo.php", "debug_page"),
        ("/setup-config.php", "installer"), ("/tinyfilemanager.php", "file_manager"),
        ("/assets/elfinder/x", "file_manager"), ("/app_dev.php", "debug_console"),
        ("/_profiler/abc", "debug_console"), ("/actuator/heapdump", "memory_dump"),
        ("/s/sfsites/aura", "salesforce_aura"),
    ])
    def test_each_kind(self, path, kind):
        assert classify_file(B + path).get("file_kind") == kind

    @pytest.mark.parametrize("path", ["/env.js", "/env", "/environment.ts", "/.github/workflows/x",
                                      "/.gitignore", "/x/id_rsa.pub", "/log", "/login", "/logout", "/blog"])
    def test_does_not_match(self, path):
        assert "file_kind" not in classify_file(B + path)

    def test_the_host_name_never_counts(self):
        assert classify_file("https://backup.example.test/") == {}

    def test_severity_of_pem_key_and_config_backups(self):
        assert classify_file(B + "/c.pem")["severity"] == "medium"
        assert classify_file(B + "/c.key")["severity"] == "high"
        assert classify_file(B + "/wp-config.php.bak")["severity"] == "high"
        assert classify_file(B + "/index.php.bak")["severity"] == "medium"

    def test_backup_archive_vs_document(self):
        assert classify_file(B + "/backup.zip")["file_kind"] == "backup"
        assert classify_file(B + "/brochure.zip") == {"document_type": "archive"}

    def test_documents_by_type_then_extension_and_raw_text(self):
        assert classify_file(B + "/x", "application/pdf") == {"document_type": "pdf"}
        assert classify_file(B + "/r.xlsx") == {"document_type": "office"}
        assert classify_file(B + "/export.csv") == {"document_type": "csv"}
        assert classify_file(B + "/env", "text/plain") == {"document_type": "raw"}
        assert classify_file(B + "/robots.txt", "text/plain") == {}


def _visit(url, uuid="u1", time="2026-10-01T00:00:00.000Z", mime="text/html"):
    host = url.split("/")[2]
    return {"page": {"url": url, "domain": host, "ip": "192.88.97.10", "status": "200", "mimeType": mime},
            "task": {"url": url, "time": time, "visibility": "public", "uuid": uuid}}


def _run(results, **settings):
    base = {"URLSCAN_ENABLED": True}
    base.update(settings)
    with patch.object(u, "_urlscan_search", return_value=u.SearchResults(results)):
        out = u.run_urlscan_enrichment({"domain": "example.test", "metadata": {}}, base)
    return out["urlscan"]


class TestProducers:
    def test_one_finding_per_host_path_and_kind_with_the_newest_scan(self):
        data = _run([_visit(B + "/.env", uuid="old", time="2026-08-01T00:00:00.000Z"),
                     _visit(B + "/.env", uuid="new", time="2026-10-01T00:00:00.000Z")])
        f, = [f for f in data["findings"] if f["type"] == "sensitive_file_seen"]
        assert (f["kind"], f["kind_field"], f["severity"]) == ("env", "file_kind", "high")
        assert f["props"]["sightings"] == 2 and f["urlscan_scan_id"] == "new"

    def test_a_web_shell_trace_is_a_finding_without_a_scan_id(self):
        data = _run([_visit(B + "/shell.php?cmd=cat+/etc/passwd")])
        f, = [f for f in data["findings"] if f["kind"] == "web_shell_trace"]
        assert f["urlscan_scan_id"] == "" and "etc/passwd" not in f["url"]
        assert data["urls_with_paths"] == []

    def test_documents_are_attributes_not_findings(self):
        data = _run([_visit(B + "/docs/invoice-2026.pdf", mime="application/pdf"),
                     _visit("https://app.example.test/export.csv", mime="text/csv")])
        assert [f for f in data["findings"] if f["type"] == "sensitive_file_seen"] == []
        types = {r["path"]: r.get("document_type") for r in data["urls_with_paths"]}
        assert types == {"/docs/invoice-2026.pdf": "pdf", "/export.csv": "csv"}
        assert {r.get("urlscan_mime_type") for r in data["urls_with_paths"]} == {"application/pdf", "text/csv"}

    def test_switches_off_no_finding_no_attribute_urls_still_flow(self):
        data = _run([_visit(B + "/.env"), _visit(B + "/a.pdf", mime="application/pdf")],
                    URLSCAN_SENSITIVE_FILES=False, URLSCAN_DOCUMENT_LINKS=False)
        assert [f for f in data["findings"] if f["type"] == "sensitive_file_seen"] == []
        assert len(data["urls_with_paths"]) == 2
        for row in data["urls_with_paths"]:
            assert "document_type" not in row and "urlscan_file_kind" not in row

    def test_the_file_kind_rides_on_the_row(self):
        data = _run([_visit(B + "/actuator/heapdump")])
        assert data["urls_with_paths"][0]["urlscan_file_kind"] == "memory_dump"


class TestRouteExposureHandover:
    def _combined(self, findings, live=(B + "/",)):
        return {"http_probe": {"by_url": {u: {"url": u, "status_code": 200} for u in live}},
                "urlscan": {"findings": findings}}

    def _file(self, path, kind, host="files.example.test"):
        return {"type": "sensitive_file_seen", "kind": kind, "host": host, "path": path,
                "url": f"https://{host}{path}"}

    def test_kinds_and_their_requests(self):
        corpus = h.harvest(self._combined([
            self._file("/.env", "env"), self._file("/backup.sql", "db_dump"),
            self._file("/actuator/heapdump", "memory_dump"), self._file("/app/.git/logs/HEAD", "vcs"),
            self._file("/install.php", "installer"), self._file("/id_rsa", "private_key"),
        ]))
        routes = {r.path: (r.request, r.generated_by, r.sources) for r in corpus.routes.values()}
        assert routes["/.env"] == ("get", "found", ("urlscan",))
        assert routes["/backup.sql"][:2] == ("backup", "backup")
        assert routes["/actuator/heapdump"][0] == "head"
        assert "/app/.git/HEAD" in routes and "/app/.git/config" in routes
        assert "/app/.git/logs/HEAD" not in routes
        assert "/install.php" not in routes and "/id_rsa" not in routes

    def test_only_live_bases(self):
        corpus = h.harvest(self._combined([self._file("/.env", "env", host="gone.example.test")]))
        assert not [r for r in corpus.routes.values() if "urlscan" in r.sources]

    @pytest.mark.parametrize("order", ["crawler_first", "urlscan_first"])
    def test_merge_keeps_the_strictest_request(self, order):
        corpus = h.Corpus(bases=[B])
        get = h.Route(baseurl=B, path="/actuator/heapdump", sources=("katana",))
        head = h.Route(baseurl=B, path="/actuator/heapdump", sources=("urlscan",), request="head")
        dump_get = h.Route(baseurl=B, path="/backup.sql", sources=("katana",))
        dump = h.Route(baseurl=B, path="/backup.sql", sources=("urlscan",), request="backup",
                       generated_by="backup")
        pairs = [(get, head), (dump_get, dump)] if order == "crawler_first" else [(head, get), (dump, dump_get)]
        for a, b in pairs:
            corpus.add(a)
            corpus.add(b)
        assert corpus.routes[(B, "/actuator/heapdump", "GET")].request == "head"
        backup = corpus.routes[(B, "/backup.sql", "GET")]
        assert (backup.request, backup.generated_by) == ("backup", "backup")

    def test_partial_builder_hands_urlscan_files_over(self):
        from recon.partial_recon_modules import graph_builders as gb
        endpoint_row = {"base": B, "host": "files.example.test", "path": "/actuator/heapdump",
                        "method": "GET", "category": "other", "sources": ["urlscan"], "creator": "urlscan",
                        "openapi_security": None, "openapi_tags": None, "declared_only": None,
                        "discovery_status": None, "urlscan_file_kind": "memory_dump"}

        session = MagicMock()

        def run(query, **kw):
            res = MagicMock()
            rows = [endpoint_row] if "urlscan_file_kind" in query else []
            res.__iter__.return_value = iter(rows)
            return res
        session.run.side_effect = run
        client = MagicMock()
        client.__enter__.return_value = client
        client.verify_connection.return_value = True
        client.driver.session.return_value.__enter__.return_value = session
        with patch("graph_db.Neo4jClient", return_value=client), \
                patch.object(gb, "graph_url_scope", return_value=lambda host: True), \
                patch.object(gb, "_graph_url_technologies", return_value={}):
            data = gb._build_route_exposure_data_from_graph(["example.test"], "u", "p", settings={})
        f, = data["urlscan"]["findings"]
        assert (f["kind"], f["path"]) == ("memory_dump", "/actuator/heapdump")
        data["http_probe"] = {"by_url": {B + "/": {"url": B + "/", "status_code": 200}}}
        route = h.harvest(data).routes[(B, "/actuator/heapdump", "GET")]
        assert route.request == "head"
