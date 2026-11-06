"""Item 4a: urlscan's addresses join by_base_url with every module's labels.

Live bases only, no value copied, the same labels as the same address from GAU,
merged before OpenAPI (a swagger address becomes a seed), and a page titled
Swagger UI is a seed whatever its path. Hosts are example.test.
"""
from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import patch

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.resource_enum import urlscan_helpers as uh  # noqa: E402
from recon.helpers.resource_enum.gau_helpers import merge_gau_into_by_base_url  # noqa: E402

LIVE = {"https://app.example.test"}


def _row(url, types=None, title=None):
    path = "/" + url.split("/", 3)[3].split("?", 1)[0] if url.count("/") >= 3 else "/"
    row = {"full_url": url, "base_url": "/".join(url.split("/")[:3]), "path": path,
           "params": {}, "param_types": types or {}}
    if title:
        row["title"] = title
    return row


def test_same_labels_as_the_same_address_from_gau():
    gau, _ = merge_gau_into_by_base_url(["https://app.example.test/api/v1/items?id=5&next=https://o.test/"],
                                        {}, None)
    us, _ = uh.merge_urlscan_into_by_base_url(
        [_row("https://app.example.test/api/v1/items?id=***&next=***", {"id": "integer", "next": "url"})],
        {}, LIVE)
    g = gau["https://app.example.test"]["endpoints"]["/api/v1/items"]
    u = us["https://app.example.test"]["endpoints"]["/api/v1/items"]
    assert u["category"] == g["category"] == "api"
    pick = lambda ep: {p["name"]: (p["category"], p["type"]) for p in ep["parameters"]["query"]}
    assert pick(u) == pick(g)
    assert u["sources"] == ["urlscan"]
    assert "sample_urls" not in u and "***" not in str(u)


def test_a_base_not_live_in_this_scan_adds_nothing():
    out, stats = uh.merge_urlscan_into_by_base_url([_row("https://old.example.test/x?a=***")], {}, LIVE)
    assert out == {} and stats["urlscan_not_live"] == 1


def test_one_path_form_with_gau():
    gau, _ = merge_gau_into_by_base_url(["https://app.example.test/docs"], {}, None)
    out, stats = uh.merge_urlscan_into_by_base_url([_row("https://app.example.test/docs/")], gau, LIVE)
    assert list(out["https://app.example.test"]["endpoints"]) == ["/docs"]
    assert out["https://app.example.test"]["endpoints"]["/docs"]["sources"] == ["gau", "urlscan"]


def test_a_title_labels_the_address():
    out, _ = uh.merge_urlscan_into_by_base_url([_row("https://app.example.test/", title="Sign in")], {}, LIVE)
    assert out["https://app.example.test"]["endpoints"]["/"]["category"] == "authentication"


def test_live_bases_are_answered_probes():
    recon = {"http_probe": {"by_url": {
        "https://app.example.test/": {"status_code": 200},
        "https://down.example.test/": {"status_code": None},
        "https://app.example.test:8443/extra": {"url": "https://app.example.test:8443/extra", "status_code": 404},
    }}}
    assert uh.live_bases(recon) == {"https://app.example.test", "https://app.example.test:8443"}


def test_title_seeds_from_urlscan_and_httpx():
    seeds = uh.title_seed_urls([_row("https://app.example.test/console/?x=***", title="Swagger UI")],
                               {"https://docs.example.test/": {"title": "ReDoc", "final_url": "https://docs.example.test/r"}})
    assert seeds == ["https://app.example.test/console/", "https://docs.example.test/r"]


def test_openapi_enqueues_a_title_seed_whatever_its_path():
    from recon.helpers.openapi import discovery as d
    enqueued = []

    class _Scope:
        def allows(self, url):
            return True

    def fake_discover(recon_data, settings, seed_urls, explicit_urls, result, title_seeds=()):
        # Mirror the auto-discover branch: what it would enqueue explicitly.
        for url in sorted(set(seed_urls) | set(title_seeds)):
            if url in set(title_seeds) or d.SPEC_LIKE_PATH.search(url.split("://", 1)[1].split("/", 1)[-1]):
                enqueued.append(url)

    source = (PROJECT_ROOT / "recon" / "helpers" / "openapi" / "discovery.py").read_text()
    assert "if url in flagged or SPEC_LIKE_PATH.search(urlsplit(url).path):" in source
    with patch.object(d, "_discover", side_effect=fake_discover):
        d.run_openapi_discovery({}, {"OPENAPI_AUTO_DISCOVER": True}, ["https://app.example.test/home"],
                                title_seeds=["https://app.example.test/console/"])
    assert enqueued == ["https://app.example.test/console/"]
    assert not d.SPEC_LIKE_PATH.search("/console/")


def test_resource_enum_merges_urlscan_before_openapi():
    source = (PROJECT_ROOT / "recon" / "main_recon_modules" / "resource_enum.py").read_text()
    assert source.index("merge_urlscan_into_by_base_url(") < source.index("run_openapi_discovery(recon_data")
