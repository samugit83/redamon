"""Leaked one-time links and secrets in the web archives' URLs (GAU, ParamSpider).

The quarantine keeps them out of every request list; they become findings
with the secret and the full links kept only in the display fields. Hosts are
example.test, tokens are invented.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.display_only import strip_display_only  # noqa: E402
from recon.helpers.archive_leaks import build_archive_leaks  # noqa: E402
from recon.helpers.resource_enum.gau_helpers import quarantine_archive_urls  # noqa: E402

T1 = "Xq8Rw2Lp7Nm4Kt9Vb3Cz6Hd"
T2 = "Pk3Tz8Wq1Nr6Ls9Bv4Ym7Jh"
K1 = "ak9Q2w8E3r7T4y6U1i0O5pLz"
SETTINGS = {}


def _leaks(urls, hmac_key="lab-key", settings=None):
    return build_archive_leaks(urls, settings or SETTINGS, "example.test", hmac_key=hmac_key)


def test_the_collector_receives_every_held_url_and_the_return_is_unchanged():
    urls = [f"https://auth.example.test/reset?token={T1}", "https://app.example.test/about"]
    held: list = []
    kept, by_domain = quarantine_archive_urls(urls, {"example.test": urls}, "GAU", collect=held)
    assert kept == ["https://app.example.test/about"]
    assert by_domain == {"example.test": ["https://app.example.test/about"]}
    assert held == [("gau", f"https://auth.example.test/reset?token={T1}")]


def test_without_a_collector_nothing_changes():
    urls = [f"https://auth.example.test/reset?token={T1}"]
    kept, _ = quarantine_archive_urls(urls, {"example.test": urls}, "GAU")
    assert kept == []


def test_a_leaked_link_groups_by_host_path_and_kind_with_every_full_link():
    out = _leaks([("gau", f"https://auth.example.test/reset?token={T1}"),
                  ("paramspider", f"https://auth.example.test/reset?token={T2}")])
    f, = out["findings"]
    assert (f["type"], f["kind"], f["host"], f["path"]) == (
        "leaked_one_time_link", "password_reset", "auth.example.test", "/reset")
    assert f["url"] == "https://auth.example.test/reset?token=***"
    assert f["props"]["unmasked_urls"] == [f"https://auth.example.test/reset?token={T1}",
                                           f"https://auth.example.test/reset?token={T2}"]
    assert f["props"]["unmasked_url"] == f"https://auth.example.test/reset?token={T1}"
    assert f["props"]["link_count"] == 2
    assert f["props"]["archive_sources"] == ["gau", "paramspider"]
    assert T1 not in json.dumps(strip_display_only(out))


def test_a_secret_keeps_its_value_and_link_for_display_and_is_keyed_by_hmac():
    out = _leaks([("gau", f"https://app.example.test/api?apikey={K1}"),
                  ("gau", f"https://app.example.test/api/v2?apikey={K1}")])
    sec, = out["url_secrets"]
    assert (sec["secret_type"], sec["param_name"], sec["count"]) == ("api_key", "apikey", 2)
    assert sec["secret_value"] == K1
    assert sec["unmasked_url"] == f"https://app.example.test/api?apikey={K1}"
    assert len(sec["value_hmac"]) == 64
    assert sec["masked_url"] == "https://app.example.test/api?apikey=***"
    assert K1 not in json.dumps(strip_display_only(out))


def test_another_org_or_an_roe_excluded_host_is_no_finding():
    out = _leaks([("gau", f"https://other.test/reset?token={T1}"),
                  ("gau", f"https://excluded.example.test/reset?token={T1}")],
                 settings={"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["excluded.example.test"]})
    assert out == {"findings": [], "url_secrets": []}


def test_a_broken_input_never_raises():
    assert build_archive_leaks([("gau", None), ("gau", 5)], {}, "example.test") == \
        {"findings": [], "url_secrets": []}
    assert build_archive_leaks(None, None, "") == {"findings": [], "url_secrets": []}
