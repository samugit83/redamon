"""Item 2: leaked one-time links and secrets in the URLs urlscan already returned.

Public visits of target hosts only, grouped (one finding per host, path and
kind; one Secret per value), nothing raw kept, and the quarantine holds even
with both switches off. Tokens are invented; hosts are example.test.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import urlscan_enrich as u  # noqa: E402

T1 = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"
T2 = "Pk3Tz8Wq1Nr6Ls9Bv4Ym7Jh"
K1 = "ak9Q2w8E3r7T4y6U1i0O5pLz"


def _visit(page_url, task_url=None, visibility="public", time="2026-10-01T00:00:00.000Z", uuid="u1"):
    host = page_url.split("/")[2]
    return {"page": {"url": page_url, "domain": host, "ip": "192.88.97.10", "status": "200"},
            "task": {"url": task_url or page_url, "time": time, "visibility": visibility, "uuid": uuid}}


def _run(results, env=None, **settings):
    base = {"URLSCAN_ENABLED": True}
    base.update(settings)
    with patch.object(u, "_urlscan_search", return_value=u.SearchResults(results)), \
            patch.dict(os.environ, env or {"REDAMON_SECRET_HMAC_KEY": ""}):
        out = u.run_urlscan_enrichment({"domain": "example.test", "metadata": {}}, base)
    return out["urlscan"]


def test_one_finding_per_host_path_and_kind_with_a_count():
    data = _run([
        _visit(f"https://auth.example.test/reset?token={T1}", time="2026-09-01T00:00:00.000Z", uuid="a"),
        _visit(f"https://auth.example.test/reset?token={T2}", time="2026-10-05T00:00:00.000Z", uuid="b"),
        _visit(f"https://app.example.test/invite/{T1}", uuid="c"),
    ])
    by = {(f["host"], f["path"], f["kind"]): f for f in data["findings"]}
    reset = by[("auth.example.test", "/reset", "password_reset")]
    assert reset["props"]["link_count"] == 2
    assert (reset["first_seen"][:10], reset["last_seen"][:10]) == ("2026-09-01", "2026-10-05")
    assert reset["severity"] == "high" and reset["kind_field"] == "link_kind"
    assert "urlscan_scan_id" not in reset
    assert ("app.example.test", "/invite/{token}", "invite") in by
    assert by[("app.example.test", "/invite/{token}", "invite")]["severity"] == "medium"


def test_a_leak_in_a_start_url_counts_too():
    data = _run([_visit("https://app.example.test/login", task_url=f"https://app.example.test/invite/{T1}")])
    assert [f["kind"] for f in data["findings"]] == ["invite"]


def test_secrets_one_per_value_with_hmac_and_never_the_value():
    results = [_visit(f"https://app.example.test/api/data?apikey={K1}", uuid="a"),
               _visit(f"https://app.example.test/api/data?apikey={K1}&x=1", uuid="b")]
    data = _run(results, env={"REDAMON_SECRET_HMAC_KEY": "lab-hmac-key"})
    sec, = data["url_secrets"]
    assert (sec["secret_type"], sec["param_name"], sec["value_length"]) == ("api_key", "apikey", len(K1))
    assert len(sec["value_hmac"]) == 64 and sec["count"] == 2
    assert sec["base_url"] == "https://app.example.test"
    assert K1 not in json.dumps(data)


def test_without_an_hmac_key_no_value_hmac():
    sec, = _run([_visit(f"https://app.example.test/api?apikey={K1}")])["url_secrets"]
    assert sec["value_hmac"] is None


def test_switches_off_no_findings_but_the_quarantine_holds():
    data = _run([_visit(f"https://auth.example.test/reset?token={T1}"),
                 _visit(f"https://app.example.test/api?apikey={K1}")],
                URLSCAN_LEAKED_LINKS=False, URLSCAN_SECRETS_IN_URLS=False)
    assert data["findings"] == [] and data["url_secrets"] == []
    assert len(data["quarantined_urls"]) == 2
    assert data["urls_with_paths"] == []


def test_each_switch_alone():
    results = [_visit(f"https://auth.example.test/reset?token={T1}")]
    links_only = _run(results, URLSCAN_SECRETS_IN_URLS=False)
    secrets_only = _run(results, URLSCAN_LEAKED_LINKS=False)
    assert links_only["findings"] and not links_only["url_secrets"]
    assert secrets_only["url_secrets"] and not secrets_only["findings"]


def test_private_visits_and_other_hosts_give_nothing():
    data = _run([
        _visit(f"https://auth.example.test/reset?token={T1}", visibility="private"),
        _visit(f"https://other.test/reset?token={T1}"),
        _visit(f"https://excluded.example.test/reset?token={T1}"),
    ], ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["excluded.example.test"])
    assert data["findings"] == [] and data["url_secrets"] == []


def test_negatives_stay_quiet():
    data = _run([_visit("https://app.example.test/x?utm_source=mail"),
                 _visit("https://app.example.test/list?page=2"),
                 _visit("https://app.example.test/x?session=abc")])
    assert data["findings"] == [] and data["url_secrets"] == []
