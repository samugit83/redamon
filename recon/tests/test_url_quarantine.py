"""S1-S3: a quarantined URL never reaches a list anything requests.

urlscan's results go to urls_with_paths, which resource enumeration, nuclei DAST
and GraphQL read; GAU and ParamSpider URLs go to verification (httpx sends every
full URL), method detection and the merge. A leaked reset link, a token, a
state-changing link with a value or a web-shell trace must stop before all of
them, in the full run and in partial recon (both use the shared helpers).
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402

T1 = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"
T2 = "9f8e7d6c5b4a39281706f5e4"


def _visit(page_url, task_url=None, ip="192.0.2.10"):
    host = page_url.split("/")[2]
    return {"page": {"url": page_url, "domain": host, "ip": ip, "status": "200"},
            "task": {"url": task_url or page_url, "time": "2026-10-01T00:00:00.000Z",
                     "visibility": "public", "uuid": "0000"}}


LEAKS = [
    _visit(f"https://auth.example.test/reset?token={T1}"),
    _visit(f"https://auth.example.test/password/reset/{T2}"),
    _visit(f"https://app.example.test/unsubscribe?u={T1}"),
    _visit("https://files.example.test/shell.php?cmd=cat+/etc/passwd"),
    _visit("https://files.example.test/shell.php?page=1"),
    _visit("https://app.example.test/login",
           task_url=f"https://app.example.test/invite/{T1}"),
]
CLEAN = [
    _visit("https://app.example.test/api/v1/items?id=5"),
    _visit("https://app.example.test/search?q=x&page=2"),
]
PLANTED = (T1, T2, "etc/passwd")


def _run(results):
    with patch.object(u, "_urlscan_search", return_value=u.SearchResults(results)):
        out = u.run_urlscan_enrichment({"domain": "example.test", "metadata": {}},
                                       {"URLSCAN_ENABLED": True})
    return out["urlscan"]


def test_quarantined_urls_never_reach_urls_with_paths():
    data = _run(LEAKS + CLEAN)
    full = [row["full_url"] for row in data["urls_with_paths"]]
    # The page a leaked invite redirected to is an ordinary page; only the
    # invite (the start URL) is quarantined.
    assert sorted(full) == sorted([v["page"]["url"] for v in CLEAN] + ["https://app.example.test/login"])
    for row in data["urls_with_paths"]:
        assert not any(t in row["full_url"] for t in PLANTED)


def test_quarantined_rows_are_masked_and_carry_no_value():
    data = _run(LEAKS)
    rows = {(r["base_url"], r["path"]) for r in data["quarantined_urls"]}
    assert ("https://auth.example.test", "/reset") in rows
    assert ("https://auth.example.test", "/password/reset/{token}") in rows
    assert ("https://app.example.test", "/unsubscribe") in rows
    assert ("https://files.example.test", "/shell.php") in rows
    assert ("https://app.example.test", "/invite/{token}") in rows
    blob = repr(data["quarantined_urls"])
    assert not any(t in blob for t in PLANTED)


def test_a_web_shell_trace_quarantines_its_whole_host_and_path():
    data = _run(LEAKS)
    shell_rows = [r for r in data["quarantined_urls"] if r["path"] == "/shell.php"]
    assert len(shell_rows) == 2
    assert any("web_shell_host" in r["reasons"] for r in shell_rows)


def test_start_url_of_another_site_is_ignored():
    data = _run([_visit("https://app.example.test/x",
                        task_url=f"https://other.test/reset?token={T1}")])
    assert data["quarantined_urls"] == []


class TestArchiveSources:
    """GAU and ParamSpider go through the same quarantine inside their shared
    discovery helpers, before verification, so the full run and partial recon
    (which calls the same helpers) both get it."""

    URLS = [f"https://a.example.test/reset?token={T1}", "https://a.example.test/about",
            f"https://a.example.test/auth/magic/{T2}"]

    def test_gau_drops_them_before_verification(self):
        from recon.helpers.resource_enum import gau_helpers
        with patch.object(gau_helpers, "run_gau_for_domain", return_value=list(self.URLS)):
            urls, by_domain = gau_helpers.run_gau_discovery(
                {"a.example.test"}, docker_image="gau", providers=["wayback"], threads=1,
                timeout=5, blacklist_extensions=[], max_urls=0, year_range=[], verbose=False,
                workers=1)
        assert urls == ["https://a.example.test/about"]
        assert by_domain["a.example.test"] == ["https://a.example.test/about"]

    def test_paramspider_drops_them(self):
        from recon.helpers.resource_enum import paramspider_helpers as ps
        urls = ["https://a.example.test/reset/FUZZ?token=FUZZ",
                f"https://a.example.test/invite/{T1}?x=FUZZ", "https://a.example.test/q?s=FUZZ"]
        with patch.object(ps, "run_paramspider_for_domain", return_value=urls):
            kept, _by = ps.run_paramspider_discovery({"a.example.test"}, "FUZZ", 5, workers=1)
        assert f"https://a.example.test/invite/{T1}?x=FUZZ" not in kept
        assert "https://a.example.test/q?s=FUZZ" in kept
        assert "https://a.example.test/reset/FUZZ?token=FUZZ" in kept
