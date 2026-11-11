"""R4: Hakrawler's seed order, ranked by Jev.

What it locks in:
- the result is always a permutation of the seeds: the order can change, the count
  never, and a fallback is the alphabetical list unchanged;
- hosts are scored from the HTTP probe's data, one item per host; above MAX_HOSTS a
  hash-chosen sample is scored (stable, and not the alphabetical cut);
- SHADOW records which half of the list each host would start in under Jev and
  under the alphabetical order, and hands Hakrawler the alphabetical list;
- partial recon keeps the alphabetical order (its probe data has nothing to rank);
- only Hakrawler gets the reordered copy: Katana and every other consumer of
  target_urls are untouched, and nothing changes with the flag off.
"""
from __future__ import annotations

from pathlib import Path
from unittest import mock

import pytest

from recon.helpers.ai_planner import crawl_seed_order as cso
from recon.helpers.ai_planner import jev_shadow

REPO = Path(__file__).resolve().parents[2]


def _resp(status=200, body=None):
    r = mock.MagicMock(status_code=status, text="")
    r.json.return_value = body if body is not None else {}
    return r


def _recon(hosts, **over):
    by_url = {}
    for i, h in enumerate(hosts):
        by_url[f"https://{h}/"] = {"url": f"https://{h}/", "host": h, "status_code": 200,
                                   "content_length": 1000 + i, "word_count": 50 + i, "line_count": 10,
                                   "title": f"Title {i}", "server": "nginx", **over}
    return {"http_probe": {"by_url": by_url}}


HOSTS = ["a.example.test", "b.example.test", "c.example.test", "d.example.test"]
SEEDS = sorted([f"https://{h}/" for h in HOSTS] + ["http://c.example.test/", "https://d.example.test/x"])


def _scores(*values):
    return {"scores": list(values), "model": "jev-1.13.0"}


def test_the_shipped_rollout_crawls_in_jev_order_and_records_each_decision(capsys):
    data = _recon(HOSTS)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, _scores(0.1, 0.2, 0.3, 0.95))) as post:
        out = cso.hakrawler_seed_order(SEEDS, data)
    assert sorted(out) == SEEDS                                    # a permutation, no seed dropped
    assert list(dict.fromkeys(cso._host(u) for u in out)) == [
        "d.example.test", "c.example.test", "b.example.test", "a.example.test"]
    sent = post.call_args.kwargs["json"]["hosts"]
    assert [h["hostname"] for h in sent] == HOSTS
    assert sent[2]["url_count"] == 2 and sent[0]["title"] == "Title 0"
    shadow = data["jev_shadow"]["crawl_seed_order"]
    assert shadow["rollout"] == "act"
    records = {r["hostname"]: r for r in shadow["records"]}
    assert records["d.example.test"]["jev"] == "early" and records["d.example.test"]["baseline"] == "late"
    assert records["a.example.test"]["jev"] == "late" and records["a.example.test"]["baseline"] == "early"
    assert records["d.example.test"]["jev_rank"] == 0 and records["d.example.test"]["conf"] == 95
    printed = capsys.readouterr().out
    assert "Jev moved 2 host(s) from the second half of the list into the first" in printed
    assert "example.test" not in printed


def test_a_shadow_rollout_keeps_the_alphabetical_list(monkeypatch, capsys):
    """The gate itself: a hook switched back to SHADOW records but changes nothing."""
    monkeypatch.setattr(cso, "ROLLOUT", jev_shadow.SHADOW)
    data = _recon(HOSTS)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, _scores(0.1, 0.2, 0.3, 0.95))):
        out = cso.hakrawler_seed_order(SEEDS, data)
    assert out == SEEDS
    assert data["jev_shadow"]["crawl_seed_order"]["rollout"] == "shadow"
    assert "Jev would move 2 host(s)" in capsys.readouterr().out


def test_act_returns_the_seeds_host_by_host_in_jev_order(monkeypatch):
    monkeypatch.setattr(cso, "ROLLOUT", jev_shadow.ACT)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, _scores(0.1, 0.9, 0.9, 0.5))):
        out = cso.hakrawler_seed_order(SEEDS, _recon(HOSTS))
    assert sorted(out) == SEEDS                                    # a permutation
    hosts_in_order = list(dict.fromkeys(cso._host(u) for u in out))
    assert hosts_in_order == ["b.example.test", "c.example.test", "d.example.test", "a.example.test"]


def test_the_shipped_rollout_is_act():
    assert cso.ROLLOUT == jev_shadow.ACT


def test_unscored_hosts_follow_in_alphabetical_order(monkeypatch):
    monkeypatch.setattr(cso, "ROLLOUT", jev_shadow.ACT)
    data = _recon(["b.example.test", "d.example.test"])            # a and c were never probed
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, _scores(0.2, 0.9))):
        out = cso.hakrawler_seed_order(SEEDS, data)
    assert list(dict.fromkeys(cso._host(u) for u in out)) == [
        "d.example.test", "b.example.test", "a.example.test", "c.example.test"]
    assert sorted(out) == SEEDS


@pytest.mark.parametrize("bad", [None, {}, _scores(0.5), _scores(0.5, 0.5, 0.5, 1.5),
                                 _scores(0.5, 0.5, 0.5, float("nan")), _scores(0.5, 0.5, 0.5, True),
                                 {"scores": "x"}])
def test_a_malformed_answer_keeps_the_alphabetical_list(bad, monkeypatch):
    monkeypatch.setattr(cso, "ROLLOUT", jev_shadow.ACT)
    data = _recon(HOSTS)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(200, bad)):
        assert cso.hakrawler_seed_order(SEEDS, data) == SEEDS
    assert data["jev_shadow"]["crawl_seed_order"]["summary"]["fallbacks"] == 1


def test_an_agent_failure_keeps_the_alphabetical_list(monkeypatch):
    monkeypatch.setattr(cso, "ROLLOUT", jev_shadow.ACT)
    with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(503, {"error_type": "jev_auth"})):
        assert cso.hakrawler_seed_order(SEEDS, _recon(HOSTS)) == SEEDS


def test_an_unexpected_error_keeps_the_alphabetical_list():
    with mock.patch.object(cso, "jev_post", side_effect=KeyError("x")):
        assert cso.hakrawler_seed_order(SEEDS, _recon(HOSTS)) == SEEDS


def test_nothing_to_rank_makes_no_call_and_prints_no_summary(capsys):
    with mock.patch.object(jev_shadow.requests, "post") as post:
        assert cso.hakrawler_seed_order(SEEDS, {"http_probe": {}}) == SEEDS
        assert cso.hakrawler_seed_order(SEEDS, None) == SEEDS
        assert cso.hakrawler_seed_order(["https://a.example.test/"], _recon(["a.example.test"])) == \
            ["https://a.example.test/"]
    post.assert_not_called()
    assert "jev-shadow" not in capsys.readouterr().out


def test_partial_recon_keeps_the_alphabetical_order(capsys):
    with mock.patch.object(jev_shadow.requests, "post") as post:
        assert cso.hakrawler_seed_order(SEEDS, _recon(HOSTS), partial=True) == SEEDS
    post.assert_not_called()
    assert "Partial recon has no per-host probe signal" in capsys.readouterr().out


def test_above_the_bound_a_stable_hash_sample_is_scored(monkeypatch):
    monkeypatch.setattr(cso, "MAX_HOSTS", 5)
    hosts = [f"h{i:02d}.example.test" for i in range(20)]
    seeds = [f"https://{h}/" for h in hosts]
    sent = []
    for _ in range(2):
        with mock.patch.object(jev_shadow.requests, "post", return_value=_resp(503, {})) as post:
            cso.hakrawler_seed_order(seeds, _recon(hosts))
        sent.append([h["hostname"] for h in post.call_args.kwargs["json"]["hosts"]])
    assert sent[0] == sent[1] and len(sent[0]) == 5                 # stable between runs
    assert sent[0] != hosts[:5]                                      # not the alphabetical cut


def test_the_shipped_bound_matches_the_agent():
    assert cso.MAX_HOSTS == 400


def test_the_root_page_is_the_host_signal():
    data = {"http_probe": {"by_url": {
        "https://a.example.test/big": {"url": "https://a.example.test/big", "content_length": 9999, "title": "Big"},
        "https://a.example.test/": {"url": "https://a.example.test/", "content_length": 10, "title": "Root"}}}}
    item = cso._host_item("a.example.test", ["https://a.example.test/", "https://a.example.test/big"],
                          data["http_probe"])
    assert item["title"] == "Root" and item["url_count"] == 2


@pytest.mark.parametrize("ai,flag,on", [(True, True, True), (True, False, False), (False, True, False)])
def test_the_hook_needs_both_switches(ai, flag, on):
    assert cso.jev_seed_order_enabled({"AI_IN_PIPELINE": ai, "HAKRAWLER_JEV_SEED_ORDER": flag}) is on


def test_only_hakrawler_gets_the_reordered_copy():
    source = (REPO / "recon/main_recon_modules/resource_enum.py").read_text()
    gate = "settings.get('AI_IN_PIPELINE') and settings.get('HAKRAWLER_JEV_SEED_ORDER')"
    assert gate in source
    assert source.index("hakrawler_seed_order(target_urls, recon_data)") < \
        source.index("with ThreadPoolExecutor(max_workers=crawler_workers) as executor:")
    hak = source[source.index("futures['hakrawler'] = executor.submit("):][:200]
    assert "hakrawler_seeds," in hak
    kat = source[source.index("futures['katana'] = executor.submit("):][:200]
    assert "target_urls," in kat and "hakrawler_seeds" not in kat


def test_partial_hakrawler_is_wired_with_the_partial_flag():
    source = (REPO / "recon/partial_recon_modules/web_crawling.py").read_text()
    assert "settings.get('AI_IN_PIPELINE') and settings.get('HAKRAWLER_JEV_SEED_ORDER')" in source
    assert "hakrawler_seed_order(target_urls, recon_data, partial=True)" in source
