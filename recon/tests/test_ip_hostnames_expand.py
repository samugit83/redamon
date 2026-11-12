"""record_filter's passive search of the filter domains (P5, design §8).

Only `*.x` include entries are searched, with record_filter and the checkbox
explicitly on; one search per domain and source: crt.sh (crt.name as its own
fallback), HackerTarget, Subfinder without -active, and urlscan
(`page.domain:x`, keyed) through urlscan_enrich's search, so a patched
URLSCAN_API_BASE (the lab hook) receives it. The names are bounded
(IP_HOSTNAME_PASSIVE_MAX_NAMES, never above the hook's per-run bound) before
any lookup, then wildcard_control.filter_late_names marks the names under a
filter domain that only its wildcard answers, and every name under a zone it
could not probe. A paused or failing source is a coverage gap and the search
goes on; with DNS lookups off it never starts. The thread gets a copy of the
settings and nothing of the run; join() waits for it, at most JOIN_BUDGET_S,
and logs one line. Past the budget the hook goes on with the names found so
far, checks them itself, notes the sources and domains not finished, and
leaves the daemon threads behind, which never start the wildcard control; a
search already in that check is waited for instead. The timing tests use
gates and events, never the clock.

The hook joins it: the names become candidates with source passive_<src>, no
ips_seen, judged by the same rule; a wildcard-dropped name seen on no target
IP is refused wildcard_zone (check 15).

Every source's HTTP (requests), Docker run and DNS answer is a fake.
Documentation ranges (RFC 5737) and reserved names only.
"""
from __future__ import annotations

import copy
import inspect
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "recon"))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers import docker_helpers  # noqa: E402
from recon.helpers import ip_hostnames as ih  # noqa: E402
from recon.helpers import ip_hostnames_expand as ipe  # noqa: E402
from recon.helpers import wildcard_control  # noqa: E402
from recon.main_recon_modules import domain_recon as dr  # noqa: E402
from recon.main_recon_modules import urlscan_enrich as us  # noqa: E402

T1, T2, FOREIGN = "203.0.113.10", "203.0.113.11", "198.51.100.7"
STUB_BASE = "http://192.0.2.30/api/v1"


@pytest.fixture(autouse=True)
def _fresh(monkeypatch):
    monkeypatch.delenv("RECON_CIRCUIT_BREAKERS", raising=False)
    circuit_breaker.reset_registry()
    dr.resolver_breaker.reset()
    # No zone answers a random label: no wildcard, unless a test says so.
    monkeypatch.setattr(wildcard_control, "_query", lambda name, rtype: ("nx", []))
    for tool in ("run_amass", "run_knockpy", "run_puredns_resolve"):
        monkeypatch.setattr(dr, tool, mock.Mock(side_effect=AssertionError(f"{tool} is never a passive source")))
    yield
    circuit_breaker.reset_registry()
    dr.resolver_breaker.reset()


def _settings(**extra):
    base = {"IP_MODE": True, "IP_HOSTNAME_MODE": "record_filter", "IP_HOSTNAME_PASSIVE_EXPAND": True,
            "IP_HOSTNAME_INCLUDE": ["*.example.com"], "IP_HOSTNAME_EXCLUDE": [],
            "IP_HOSTNAME_PASSIVE_MAX_NAMES": 500, "IP_HOSTNAME_MAX_SCANNED": 100,
            "DNS_ENABLED": True, "ROE_ENABLED": False,
            "CRTSH_ENABLED": True, "HACKERTARGET_ENABLED": True, "SUBFINDER_ENABLED": True,
            "URLSCAN_ENABLED": True, "URLSCAN_API_KEY": "lab-key"}
    base.update(extra)
    return base


def _resp(status=200, body=None, text="", headers=None):
    resp = mock.MagicMock()
    resp.status_code = status
    resp.headers = headers or {}
    resp.text = text
    resp.json.return_value = body
    return resp


class Net:
    """Every passive source's network, by domain: a list of names, or an
    HTTP status (an int) for a failure. Records every request."""

    def __init__(self, crtsh=None, hackertarget=None, urlscan=None, subfinder=None, crtname=None):
        self.answers = {"crtsh": crtsh or {}, "hackertarget": hackertarget or {},
                        "urlscan": urlscan or {}, "subfinder": subfinder or {}, "crtname": crtname or {}}
        self.gets, self.urlscan_calls, self.docker, self.crtname_calls = [], [], [], []

    def _answer(self, source, domain):
        return self.answers[source].get(domain, [])

    def install(self, monkeypatch):
        net = self

        class Session:
            def get(self, url, params=None, timeout=None, **_kw):
                net.gets.append(url)
                if "crt.sh/" in url:
                    domain = url.split("q=%.", 1)[1].split("&", 1)[0]
                    answer = net._answer("crtsh", domain)
                    if isinstance(answer, int):
                        return _resp(answer, body=[])
                    return _resp(200, body=[{"name_value": "\n".join(answer)}])
                if "hackertarget" in url:
                    domain = url.split("q=", 1)[1]
                    answer = net._answer("hackertarget", domain)
                    if isinstance(answer, int):
                        return _resp(answer, text="error")
                    return _resp(200, text="\n".join(f"{n},{T1}" for n in answer))
                raise AssertionError(f"unexpected request {url}")

            def close(self):
                pass

        def urlscan_get(url, params=None, headers=None, timeout=None):
            net.urlscan_calls.append({"url": url, "params": dict(params or {}), "headers": dict(headers or {})})
            domain = params["q"].split("page.domain:", 1)[1]
            answer = net._answer("urlscan", domain)
            if isinstance(answer, int):
                return _resp(answer, body={"message": "x"})
            results = [{"page": {"domain": n}, "task": {"domain": n}, "sort": [i, f"u{i}"]}
                       for i, n in enumerate(answer)]
            return _resp(200, body={"results": results, "total": len(results)})

        def run_tool_container(cmd, *, tool, timeout):
            net.docker.append(list(cmd))
            domain = cmd[cmd.index("-d") + 1]
            answer = net._answer("subfinder", domain)
            if isinstance(answer, int):
                return SimpleNamespace(returncode=answer, stdout="", stderr="boom", timed_out=False)
            return SimpleNamespace(returncode=0, stdout="\n".join(json.dumps({"host": n}) for n in answer),
                                   stderr="", timed_out=False)

        def crtname_fetch(domain):
            net.crtname_calls.append(domain)
            answer = net._answer("crtname", domain)
            return (None, False) if isinstance(answer, int) or answer == [] else (list(answer), False)

        monkeypatch.setattr(dr.requests, "Session", Session)
        monkeypatch.setattr(us.requests, "get", urlscan_get)
        monkeypatch.setattr(docker_helpers, "run_tool_container", run_tool_container)
        monkeypatch.setattr(dr, "_crtname_fetch", crtname_fetch)
        return self


def _gaps():
    return {(g["source"], g["module"]): g for g in circuit_breaker.coverage_report().gaps}


def _search(settings=None, domains=("example.com",), roots=None):
    return ipe.search(list(domains), list(roots if roots is not None else domains), settings or _settings())


# ---------------------------------------------------------------------------
# The sources: one search per domain each, the names tagged by source
# ---------------------------------------------------------------------------

def test_every_source_is_asked_once_and_its_names_are_tagged(monkeypatch, capsys):
    net = Net(crtsh={"example.com": ["a.example.com"]}, hackertarget={"example.com": ["b.example.com"]},
              urlscan={"example.com": ["c.example.com", "a.example.com"]},
              subfinder={"example.com": ["d.example.com"]}).install(monkeypatch)
    found = _search()
    assert found.names == {"a.example.com": ("passive_crtsh", "passive_urlscan"),
                           "b.example.com": ("passive_hackertarget",), "c.example.com": ("passive_urlscan",),
                           "d.example.com": ("passive_subfinder",)}
    # The sources run in parallel: the order of their requests is not fixed.
    assert sorted(net.gets) == ["https://api.hackertarget.com/hostsearch/?q=example.com",
                                "https://crt.sh/?q=%.example.com&output=json"]
    assert len(net.urlscan_calls) == 1 and net.urlscan_calls[0]["params"]["q"] == "page.domain:example.com"
    assert net.urlscan_calls[0]["headers"] == {"API-Key": "lab-key"}
    assert len(net.docker) == 1
    assert found.log_line() == ("[*][IpNames] Passive search: 1 domain, 4 names "
                                "(crt.sh 1, hackertarget 1, subfinder 1, urlscan 2)")
    assert found.summary() == {"queried": 1, "names": 4, "truncated": 0, "wildcard_zone": 0,
                               "sources": {"crtsh": 1, "hackertarget": 1, "subfinder": 1, "urlscan": 2},
                               "not_searched": {}, "not_finished": {}}
    assert _gaps() == {}


def test_two_domains_are_two_searches_per_source(monkeypatch):
    net = Net(crtsh={"example.com": ["a.example.com"], "example.net": ["x.example.net", "y.example.net"]}
              ).install(monkeypatch)
    found = _search(_settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.example.net"]),
                    domains=("example.com", "example.net"))
    assert sorted(found.names) == ["a.example.com", "x.example.net", "y.example.net"]
    assert sorted(u for u in net.gets if "crt.sh" in u) == [
        "https://crt.sh/?q=%.example.com&output=json", "https://crt.sh/?q=%.example.net&output=json"]
    assert sorted(c["params"]["q"] for c in net.urlscan_calls) == ["page.domain:example.com",
                                                                   "page.domain:example.net"]
    assert sorted(cmd[cmd.index("-d") + 1] for cmd in net.docker) == ["example.com", "example.net"]
    assert found.log_line().startswith("[*][IpNames] Passive search: 2 domains, 3 names (crt.sh 3, ")


def test_only_strict_subdomains_of_the_searched_domain_are_kept(monkeypatch):
    Net(crtsh={"example.com": ["example.com", "*.example.com", "Mail.Example.COM.", "other.test",
                               "admin@x.example.com", "deep.a.example.com"]},
        hackertarget={"example.com": [FOREIGN, "evil-example.com", "ip-targets.example.com"]},
        urlscan={"example.com": ["notexample.com", "", "www.example.com"]}).install(monkeypatch)
    found = _search()
    assert sorted(found.names) == ["deep.a.example.com", "mail.example.com", "www.example.com"]


def test_crt_name_answers_when_crt_sh_does_not(monkeypatch):
    net = Net(crtsh={"example.com": 502}, crtname={"example.com": ["x.example.com"]}).install(monkeypatch)
    found = _search()
    assert net.crtname_calls == ["example.com"]
    assert found.names["x.example.com"] == ("passive_crtname",)
    assert "crt.sh 1" in found.log_line()
    assert ("passive_crtsh", "ip_hostnames") not in _gaps()


def test_subfinder_runs_its_passive_sources_only(monkeypatch):
    net = Net(subfinder={"example.com": ["s.example.com"]}).install(monkeypatch)
    _search()
    (cmd,) = net.docker
    assert "-active" not in cmd
    assert cmd[cmd.index("-d") + 1] == "example.com"
    assert "projectdiscovery/subfinder" in " ".join(cmd)


def test_urlscan_goes_to_the_base_url_the_lab_hook_sets(monkeypatch):
    net = Net(urlscan={"example.com": ["hidden.example.com"]}).install(monkeypatch)
    monkeypatch.setattr(us, "URLSCAN_API_BASE", STUB_BASE)
    found = _search()
    assert [c["url"] for c in net.urlscan_calls] == [f"{STUB_BASE}/search/"]
    assert found.names == {"hidden.example.com": ("passive_urlscan",)}


@pytest.mark.parametrize("extra", [{"URLSCAN_API_KEY": ""}, {"URLSCAN_ENABLED": False}])
def test_urlscan_is_asked_only_with_its_toggle_and_a_key(monkeypatch, extra):
    net = Net(urlscan={"example.com": ["c.example.com"]}).install(monkeypatch)
    found = _search(_settings(**extra))
    assert net.urlscan_calls == []
    assert "urlscan" not in found.log_line() and found.names == {}
    assert "urlscan" not in found.summary()["sources"] and "urlscan" not in found.summary()["not_searched"]


@pytest.mark.parametrize("toggle,source", [("CRTSH_ENABLED", "crt.sh"), ("HACKERTARGET_ENABLED", "hackertarget"),
                                           ("SUBFINDER_ENABLED", "subfinder")])
def test_a_source_switched_off_is_not_asked(monkeypatch, toggle, source):
    net = Net().install(monkeypatch)
    found = _search(_settings(**{toggle: False}))
    assert f"{source} " not in found.log_line()
    if source == "subfinder":
        assert net.docker == []
    else:
        assert not any(("crt.sh" if source == "crt.sh" else "hackertarget") in u for u in net.gets)


# ---------------------------------------------------------------------------
# Only `*.x` entries, record_filter, the checkbox
# ---------------------------------------------------------------------------

def test_only_wildcard_include_entries_are_searched():
    roots, domains = ipe.plan(_settings(IP_HOSTNAME_INCLUDE=[
        "*.example.com", "exact.example.org", "*example.net", "*.app.example.com"]))
    assert roots == ["example.com", "example.net", "app.example.com"]
    # app.example.com's names are in example.com's answer: one search covers both.
    assert domains == ["example.com", "example.net"]


def test_no_wildcard_entry_starts_nothing(capsys):
    assert ipe.start(_settings(IP_HOSTNAME_INCLUDE=["exact.example.org"])) is None
    assert "[-][IpNames] Passive search: no *.<domain> include entry to search" in capsys.readouterr().out


@pytest.mark.parametrize("include,extra,why", [
    (["*.example.gov"], {}, "the hard guardrail protects it"),
    (["*.example.com"], {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["example.com"]}, "the RoE excludes it"),
    (["*.example.com"], {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["*.example.com"]}, "the RoE excludes it"),
    (["*.example.com"], {"IP_HOSTNAME_EXCLUDE": ["*.example.com"]}, "an exclude entry covers it"),
    (["*.co.uk"], {}, "a public suffix reaches every registrant"),
])
def test_a_root_no_name_under_could_be_scanned_is_not_searched(capsys, include, extra, why):
    roots, domains = ipe.plan(_settings(IP_HOSTNAME_INCLUDE=include, **extra))
    assert domains == []
    assert f"[-][IpNames] Passive search skips {include[0]}: {why}" in capsys.readouterr().out


def test_an_roe_exclusion_of_one_host_keeps_the_search():
    _, domains = ipe.plan(_settings(ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["old.example.com", FOREIGN]))
    assert domains == ["example.com"]


@pytest.mark.parametrize("mode", ["ip_only", "record_only", "scan_all"])
def test_no_search_outside_record_filter(monkeypatch, mode):
    called = mock.Mock()
    monkeypatch.setattr(ipe, "search", called)
    assert ipe.start(_settings(IP_HOSTNAME_MODE=mode)) is None
    called.assert_not_called()


@pytest.mark.parametrize("value", [False, None, "true", 1])
def test_no_search_unless_the_checkbox_is_true(monkeypatch, value):
    called = mock.Mock()
    monkeypatch.setattr(ipe, "search", called)
    settings = _settings(IP_HOSTNAME_PASSIVE_EXPAND=value)
    if value is None:
        del settings["IP_HOSTNAME_PASSIVE_EXPAND"]
    assert ipe.start(settings) is None
    called.assert_not_called()


@pytest.mark.parametrize("value", [False, None, 0])
def test_no_search_with_dns_lookups_off(monkeypatch, capsys, value):
    called = mock.Mock()
    monkeypatch.setattr(ipe, "search", called)
    assert ipe.start(_settings(DNS_ENABLED=value)) is None
    called.assert_not_called()
    assert ("[-][IpNames] Passive search skipped: DNS lookups are off, so no name it found could be scanned"
            in capsys.readouterr().out)


def test_start_never_raises(monkeypatch, capsys):
    monkeypatch.setattr(ipe, "plan", mock.Mock(side_effect=RuntimeError("x")))
    assert ipe.start(_settings()) is None
    assert "[!][IpNames] Passive search not started (RuntimeError)" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# Caps, before any lookup
# ---------------------------------------------------------------------------

def _checked(names, roots, dropped=()):
    """The control's answer with every zone probed and plain (no wildcard),
    `dropped` aside."""
    zones = set(wildcard_control.assign_zones(list(names), list(roots)).values())
    return wildcard_control.FilterResult(kept=[n for n in names if n not in dropped],
                                         dropped=[n for n in names if n in dropped],
                                         zones={z: {"is_wildcard": False, "ips": []} for z in zones})


def _spy_filter(monkeypatch, dropped=()):
    calls = []

    def spy(names, roots, settings, label="late"):
        calls.append({"names": list(names), "roots": list(roots), "settings": settings, "label": label})
        return _checked(names, roots, dropped)

    monkeypatch.setattr(wildcard_control, "filter_late_names", spy)
    return calls


def test_the_cap_comes_before_any_lookup_and_is_fair_to_every_domain(monkeypatch):
    Net(crtsh={"example.com": [f"{c}.example.com" for c in "abcd"],
               "example.net": [f"{c}.example.net" for c in "wxyz"]}).install(monkeypatch)
    calls = _spy_filter(monkeypatch)
    settings = _settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.example.net"], IP_HOSTNAME_PASSIVE_MAX_NAMES=3)
    found = _search(settings, domains=("example.com", "example.net"))
    # One of each domain in turn, each in name order.
    assert calls[0]["names"] == ["a.example.com", "b.example.com", "w.example.net"]
    assert sorted(found.names) == ["a.example.com", "b.example.com", "w.example.net"]
    assert found.truncated == 5
    assert found.log_line().endswith("; 5 more not kept (passive search limit)")
    assert found.summary()["truncated"] == 5


def test_the_per_run_candidate_bound_caps_the_passive_limit(monkeypatch):
    Net(crtsh={"example.com": [f"{c}.example.com" for c in "abcd"]}).install(monkeypatch)
    monkeypatch.setattr(ipe, "MAX_CANDIDATES_PER_RUN", 2)
    found = _search(_settings(IP_HOSTNAME_PASSIVE_MAX_NAMES=500))
    assert sorted(found.names) == ["a.example.com", "b.example.com"] and found.truncated == 2


def test_names_an_exclude_entry_refuses_are_cut_first(monkeypatch):
    Net(crtsh={"example.com": ["aaa.example.com", "bbb.example.com", "ccc.example.com"]}).install(monkeypatch)
    found = _search(_settings(IP_HOSTNAME_EXCLUDE=["aaa.example.com"], IP_HOSTNAME_PASSIVE_MAX_NAMES=2))
    assert sorted(found.names) == ["bbb.example.com", "ccc.example.com"]


@pytest.mark.parametrize("value,limit", [(None, 500), ("junk", 500), (7, 7), (0, 0), (-3, 0), (10**9, 20000)])
def test_the_limit_reads_any_value(value, limit):
    assert ipe._limit({"IP_HOSTNAME_PASSIVE_MAX_NAMES": value}) == limit


def test_the_default_limit_is_the_registry_default():
    from recon.project_settings import DEFAULT_SETTINGS
    assert ipe.DEFAULT_MAX_NAMES == DEFAULT_SETTINGS["IP_HOSTNAME_PASSIVE_MAX_NAMES"]
    assert ipe._limit({}) == ipe.DEFAULT_MAX_NAMES


# ---------------------------------------------------------------------------
# Breakers and failures: a coverage note, the search goes on
# ---------------------------------------------------------------------------

def _subsrc(name):
    return circuit_breaker.get_breaker(f"subsrc:{name}", label="Subdomains",
                                       threshold=circuit_breaker.INTERNAL_THRESHOLD)


def test_an_open_breaker_skips_its_source_with_a_coverage_note(monkeypatch):
    net = Net(crtsh={"example.com": ["a.example.com"]},
              hackertarget={"example.com": ["b.example.com"]}).install(monkeypatch)
    _subsrc("hackertarget").force_open("test")
    found = _search()
    assert not any("hackertarget" in u for u in net.gets)
    assert sorted(found.names) == ["a.example.com"]
    gap = _gaps()[("passive_hackertarget", "ip_hostnames")]
    assert gap["skipped"] == 1 and "paused" in gap["reason"]
    assert "hackertarget paused" in found.log_line()
    assert found.summary()["not_searched"] == {"hackertarget": 1}


def test_crt_sh_is_paused_only_when_crt_name_is_too(monkeypatch):
    net = Net(crtname={"example.com": ["x.example.com"]}).install(monkeypatch)
    _subsrc("crtsh").force_open("test")
    assert "x.example.com" in _search().names
    circuit_breaker.reset_registry()
    _subsrc("crtsh").force_open("test")
    _subsrc("crtname").force_open("test")
    found = _search()
    assert "crt.sh paused" in found.log_line()
    assert ("passive_crtsh", "ip_hostnames") in _gaps()
    assert not any("crt.sh" in u for u in net.gets) and net.crtname_calls == ["example.com"]


def test_an_open_urlscan_breaker_skips_urlscan(monkeypatch):
    net = Net(urlscan={"example.com": ["c.example.com"]}).install(monkeypatch)
    circuit_breaker.get_breaker(us.MAIN_BREAKER, label="URLScan", parent="urlscan").force_open("test")
    found = _search()
    assert net.urlscan_calls == [] and "urlscan paused" in found.log_line()
    assert ("passive_urlscan", "ip_hostnames") in _gaps()


@pytest.mark.parametrize("source,label", [("hackertarget", "hackertarget"), ("urlscan", "urlscan"),
                                          ("subfinder", "subfinder"), ("crtsh", "crt.sh")])
def test_a_failing_source_is_a_gap_and_the_others_still_answer(monkeypatch, source, label):
    answers = {"crtsh": {"example.com": ["a.example.com"]}, "hackertarget": {"example.com": ["b.example.com"]},
               "urlscan": {"example.com": ["c.example.com"]}, "subfinder": {"example.com": ["d.example.com"]}}
    answers[source] = {"example.com": 502 if source != "subfinder" else 1}
    Net(**answers).install(monkeypatch)
    found = _search()
    assert len(found.names) == 3
    assert f"{label} failed" in found.log_line()
    gap = _gaps()[(f"passive_{source}", "ip_hostnames")]
    assert gap["skipped"] == 1 and gap["reason"] == "passive search got no answer"


def test_a_source_answering_one_domain_of_two_says_so(monkeypatch):
    Net(hackertarget={"example.com": ["b.example.com"], "example.net": 502}).install(monkeypatch)
    found = _search(_settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.example.net"]),
                    domains=("example.com", "example.net"))
    assert "hackertarget 1 [1 domain not searched]" in found.log_line()
    assert found.summary()["sources"]["hackertarget"] == 1


def test_a_crashing_source_is_a_gap(monkeypatch, capsys):
    Net(crtsh={"example.com": ["a.example.com"]}).install(monkeypatch)
    monkeypatch.setitem(ipe._CALLS, "subfinder", mock.Mock(side_effect=RuntimeError("boom")))
    found = _search()
    assert sorted(found.names) == ["a.example.com"]
    assert "[!][IpNames] Passive search: subfinder failed (RuntimeError)" in capsys.readouterr().out
    assert ("passive_subfinder", "ip_hostnames") in _gaps()


def test_breakers_off_still_searches(monkeypatch):
    monkeypatch.setenv("RECON_CIRCUIT_BREAKERS", "off")
    Net(hackertarget={"example.com": ["b.example.com"]}).install(monkeypatch)
    assert "b.example.com" in _search().names


# ---------------------------------------------------------------------------
# Wildcard DNS control: settings, filter roots, fail closed
# ---------------------------------------------------------------------------

def test_filter_late_names_gets_the_settings_and_the_filter_roots(monkeypatch):
    Net(crtsh={"example.com": ["ghost.example.com", "real.example.com", "x.app.example.com"]}).install(monkeypatch)
    calls = _spy_filter(monkeypatch, dropped={"ghost.example.com"})
    settings = _settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.app.example.com"])
    found = ipe.search(["example.com"], ["example.com", "app.example.com"], settings)
    (call,) = calls
    assert call["settings"] is settings and call["label"] == "ip_hostnames"
    assert call["roots"] == ["example.com", "app.example.com"]
    assert call["names"] == ["ghost.example.com", "real.example.com", "x.app.example.com"]
    assert found.wildcard_zone == frozenset({"ghost.example.com"})
    assert found.summary()["wildcard_zone"] == 1


def test_the_control_drops_a_name_only_the_wildcard_answers(monkeypatch):
    Net(crtsh={"example.com": ["ghost.example.com", "real.example.com"]}).install(monkeypatch)
    asked = []

    def query(name, rtype):
        asked.append((name, rtype))
        if rtype != "A":
            return "none", []
        if name.startswith("rdm-") or name == "ghost.example.com":
            return "ok", [T1]
        return ("ok", [T2]) if name == "real.example.com" else ("nx", [])

    monkeypatch.setattr(wildcard_control, "_query", query)
    found = _search()
    assert found.wildcard_zone == frozenset({"ghost.example.com"})
    assert any(name.startswith("rdm-") and name.endswith(".example.com") for name, _ in asked)


def test_a_failing_control_refuses_every_passive_name(monkeypatch, capsys):
    Net(crtsh={"example.com": ["a.example.com", "b.example.com"]}).install(monkeypatch)
    monkeypatch.setattr(wildcard_control, "filter_late_names", mock.Mock(side_effect=RuntimeError("x")))
    found = _search()
    assert found.wildcard_zone == frozenset({"a.example.com", "b.example.com"})
    assert "Wildcard DNS check of the passive names failed (RuntimeError)" in capsys.readouterr().out
    assert ("passive_search", "ip_hostnames") in _gaps()


def test_a_zone_the_control_could_not_probe_refuses_its_passive_names(monkeypatch, capsys):
    """The control keeps a name whose zone it could not probe; a passive name
    there would be scanned unchecked, so check 15 gets it (I-6). A zone that
    answered keeps its names."""
    Net(crtsh={"example.com": ["a.example.com", "b.example.com"], "example.net": ["x.example.net"]}
        ).install(monkeypatch)
    monkeypatch.setattr(wildcard_control, "_query",
                        lambda name, rtype: ("fail", []) if name.endswith(".example.com") else ("nx", []))
    found = _search(_settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.example.net"]),
                    domains=("example.com", "example.net"))
    assert sorted(found.names) == ["a.example.com", "b.example.com", "x.example.net"]
    assert found.wildcard_zone == frozenset({"a.example.com", "b.example.com"})
    assert ("[!][IpNames] Wildcard DNS could not be checked for 2 passive name(s): none of them is scanned"
            in capsys.readouterr().out)


def test_no_name_no_control(monkeypatch):
    Net().install(monkeypatch)
    calls = _spy_filter(monkeypatch)
    assert _search().wildcard_zone == frozenset() and calls == []


# ---------------------------------------------------------------------------
# The thread: settings copy only, never the run; join waits and ends it
# ---------------------------------------------------------------------------

def test_the_thread_is_handed_a_copy_of_the_settings_and_nothing_of_the_run(monkeypatch):
    assert list(inspect.signature(ipe.start).parameters) == ["settings"]
    source = inspect.getsource(ipe)
    assert "save_recon_file" not in source and "combined_result" not in source
    seen = {}
    gate = threading.Event()

    def fake_search(domains, roots, settings, answers=None, claim=None):
        gate.wait(300)
        seen["settings"] = dict(settings)
        return ipe.Found(domains=tuple(domains), names={"hidden.example.com": ("passive_urlscan",)})

    monkeypatch.setattr(ipe, "search", fake_search)
    run = {"metadata": {"ip_mode": True, "expanded_ips": [T1]}, "dns": {"subdomains": {}}, "subdomains": []}
    frozen = copy.deepcopy(run)
    settings = _settings()
    search = ipe.start(settings)
    settings["IP_HOSTNAME_INCLUDE"] = ["*.changed.example"]
    gate.set()
    found = search.join()
    assert seen["settings"]["IP_HOSTNAME_INCLUDE"] == ["*.example.com"]
    assert found.names == {"hidden.example.com": ("passive_urlscan",)}
    assert run == frozen


def _alive(prefix):
    return [t for t in threading.enumerate() if t.name.startswith(prefix) and t.is_alive()]


class _OpensWhenWaitedOn:
    """The search's done event; the hook's first wait opens `gate` first, so
    the search ends only once the hook is waiting for it."""

    def __init__(self, real, gate):
        self.real, self.gate = real, gate

    def wait(self, timeout=None):
        self.gate.set()
        return self.real.wait(timeout)

    def is_set(self):
        return self.real.is_set()

    def set(self):
        self.real.set()


def test_join_waits_for_the_search_and_ends_its_thread(monkeypatch, capsys):
    gate = threading.Event()

    def slow(domains, roots, settings, answers=None, claim=None):
        gate.wait(300)
        return ipe.Found(domains=tuple(domains))

    monkeypatch.setattr(ipe, "search", slow)
    search = ipe.start(_settings())
    assert _alive("ipn-passive")
    search._done = _OpensWhenWaitedOn(search._done, gate)
    found = search.join()
    assert found.domains == ("example.com",)
    assert not _alive("ipn-passive")
    out = capsys.readouterr().out
    assert "[*][IpNames] Passive search started for 1 domain: example.com" in out
    assert "[*][IpNames] Waiting for the passive search to finish" in out
    assert "[*][IpNames] Passive search: 1 domain, 0 names" in out
    assert search.join() is found
    assert "Passive search: 1 domain" not in capsys.readouterr().out


def test_a_crashed_search_hands_over_no_name(monkeypatch, capsys):
    monkeypatch.setattr(ipe, "search", mock.Mock(side_effect=RuntimeError("x")))
    found = ipe.start(_settings()).join()
    assert found.names == {} and found.domains == ("example.com",)
    assert "[!][IpNames] Passive search failed (RuntimeError): no name from it this run" in capsys.readouterr().out
    assert ("passive_search", "ip_hostnames") in _gaps()
    assert not _alive("ipn-passive")


def test_the_real_thread_end_to_end(monkeypatch):
    Net(urlscan={"example.com": ["hidden.example.com"]}).install(monkeypatch)
    monkeypatch.setattr(us, "URLSCAN_API_BASE", STUB_BASE)
    found = ipe.start(_settings()).join()
    assert found.names == {"hidden.example.com": ("passive_urlscan",)}


# ---------------------------------------------------------------------------
# The join budget: the hook goes on, the threads are left behind
# ---------------------------------------------------------------------------

@pytest.fixture
def release(monkeypatch):
    """The gate a slow source waits on. Opened at teardown, while the
    patches still stand, and the threads left behind are let finish so
    they note nothing into the next test's registry."""
    gate = threading.Event()
    yield gate
    gate.set()
    for thread in [t for t in threading.enumerate() if t.name.startswith("ipn-")]:
        thread.join(60)


def _sources(monkeypatch, gate, slow):
    """crt.sh, Subfinder and urlscan answer `<letter>.<domain>` at once, except
    each (source, domain) in `slow`, which waits for the gate (opened by the
    test or at teardown, never by the clock). HackerTarget is switched off by
    the tests' settings."""
    def make(source):
        def call(domain, settings):
            if (source, domain) in slow:
                gate.wait(300)
            return {f"{source[0]}.{domain}": f"passive_{source}"}
        return call
    for source in ("crtsh", "subfinder", "urlscan"):
        monkeypatch.setitem(ipe._CALLS, source, make(source))


def _until(ready, what):
    """Wait for something another thread does; the limit only ends a failure."""
    end = time.monotonic() + 60
    while not ready():
        assert time.monotonic() < end, f"{what} never happened"
        time.sleep(0.01)


def _answered(search, **done):
    """True once each named source has finished exactly these domains."""
    return all(search.answers[source].snapshot().done == list(domains) for source, domains in done.items())


class _Expired:
    """The search's done event as the hook sees it when its budget has run out:
    every timed wait fails at once, whatever the clock says. An untimed wait
    first calls `then`, so the search can only finish once the hook waits."""

    def __init__(self, real, then):
        self.real, self.then = real, then

    def wait(self, timeout=None):
        if timeout is not None:
            return False
        self.then()
        return self.real.wait()

    def is_set(self):
        return self.real.is_set()

    def set(self):
        self.real.set()


def _alive_behind():
    return [t for t in threading.enumerate() if t.name.startswith("ipn-") and t.is_alive()]


def _control_callers(monkeypatch, dropped=(), hold=None, entered=None):
    """Replace the wildcard control; record the thread that runs it. With
    `hold`, the search thread's call sets `entered` and waits for it."""
    callers = []

    def control(names, roots, settings, label="late"):
        callers.append(threading.current_thread().name)
        if hold is not None and threading.current_thread().name == "ipn-passive":
            entered.set()
            hold.wait(300)
        return _checked(names, roots, dropped)

    monkeypatch.setattr(wildcard_control, "filter_late_names", control)
    return callers


def test_the_default_budget_is_900_seconds(monkeypatch):
    monkeypatch.setattr(ipe, "search", mock.Mock(return_value=ipe.Found(domains=("example.com",))))
    search = ipe.start(_settings())
    assert ipe.JOIN_BUDGET_S == 900 and search.budget == 900
    search.join()


def test_past_the_budget_the_hook_goes_on_with_what_came(monkeypatch, release, capsys):
    # Budget 0: the slow sources hold until the gate opens, so the wait ends
    # at once whatever the load; the fast answers are awaited first.
    monkeypatch.setattr(ipe, "JOIN_BUDGET_S", 0)
    _sources(monkeypatch, release, slow={("subfinder", "example.com"), ("subfinder", "example.net"),
                                         ("urlscan", "example.net")})
    callers = _control_callers(monkeypatch)
    search = ipe.start(_settings(IP_HOSTNAME_INCLUDE=["*.example.com", "*.example.net"],
                                 HACKERTARGET_ENABLED=False))
    _until(lambda: _answered(search, crtsh=["example.com", "example.net"], urlscan=["example.com"]),
           "the fast sources' answers")
    found = search.join()
    assert sorted(found.names) == ["c.example.com", "c.example.net", "u.example.com"]
    assert found.unfinished == {"subfinder": ("example.com", "example.net"), "urlscan": ("example.net",)}
    out = capsys.readouterr().out
    assert "[*][IpNames] Waiting for the passive search to finish (at most 0 s)" in out
    assert ("[!][IpNames] Passive search over its 0 s budget: going on with the names found so far; "
            "not finished: subfinder (example.com, example.net); urlscan (example.net)") in out
    assert found.log_line() == ("[*][IpNames] Passive search: 2 domains, 3 names "
                                "(crt.sh 2, subfinder not finished, urlscan 1 [1 domain not finished])")
    assert found.summary()["not_finished"] == {"subfinder": 2, "urlscan": 1}
    gaps = _gaps()
    assert gaps[("passive_subfinder", "ip_hostnames")]["skipped"] == 2
    assert gaps[("passive_subfinder", "ip_hostnames")]["reason"] == (
        "not finished in the time budget: example.com, example.net")
    assert gaps[("passive_urlscan", "ip_hostnames")]["skipped"] == 1
    # Left behind, never joined: daemons, which cannot hold the process open.
    behind = _alive_behind()
    assert behind and all(t.daemon for t in behind)
    assert search.join() is found
    # Let the abandoned search end: it never starts the wildcard control (whose
    # worker pool the interpreter would wait for); the hook ran it.
    release.set()
    search._thread.join(60)
    assert not search._thread.is_alive() and search._result is None
    assert callers == [threading.current_thread().name]


def test_the_hook_scans_what_came_before_the_budget(armed, monkeypatch, release):
    monkeypatch.setattr(ipe, "JOIN_BUDGET_S", 0)
    _sources(monkeypatch, release, slow={("subfinder", "example.com")})
    settings = _settings(HACKERTARGET_ENABLED=False)
    search = ipe.start(settings)
    _until(lambda: _answered(search, crtsh=["example.com"], urlscan=["example.com"]), "the fast sources' answers")
    block = ih.hostname_step(_run(), settings, resolve=lambda name: [T1], late_scan=mock.Mock(return_value={}),
                             passive_search=search)
    reasons = {name: c["reason"] for name, c in block["candidates"].items()}
    assert reasons == {"app.example.com": "scanned", "c.example.com": "scanned", "u.example.com": "scanned"}
    assert block["summary"]["expansion"]["not_finished"] == {"subfinder": 1}


def test_a_search_already_checking_its_names_is_waited_for(monkeypatch, release, capsys):
    _sources(monkeypatch, release, slow=set())
    entered = threading.Event()
    callers = _control_callers(monkeypatch, dropped={"s.example.com"}, hold=release, entered=entered)
    search = ipe.start(_settings(HACKERTARGET_ENABLED=False))
    assert entered.wait(60)
    # The budget runs out now; the search may finish only once the hook waits.
    search._done = _Expired(search._done, then=release.set)
    found = search.join()
    assert callers == ["ipn-passive"]
    assert sorted(found.names) == ["c.example.com", "s.example.com", "u.example.com"]
    assert found.unfinished == {} and found.wildcard_zone == frozenset({"s.example.com"})
    assert ("[*][IpNames] Passive search over its 900 s budget while checking its names for wildcard DNS: "
            "waiting for that check") in capsys.readouterr().out
    assert not search._thread.is_alive()
    assert _gaps() == {}


def test_sources_that_answered_as_the_budget_ran_out_leave_nothing_unfinished(monkeypatch, release, capsys):
    monkeypatch.setattr(ipe, "JOIN_BUDGET_S", 0)
    entered, claimed = threading.Event(), []

    def search(domains, roots, settings, answers=None, claim=None):
        for answer in answers.values():
            with answer.lock:
                answer.done = list(domains)
        entered.set()
        release.wait(300)
        claimed.append(claim())

    monkeypatch.setattr(ipe, "search", search)
    handle = ipe.start(_settings())
    assert entered.wait(60)
    found = handle.join()
    assert found.unfinished == {} and found.names == {}
    assert "not finished: nothing (its sources had just answered)" in capsys.readouterr().out
    release.set()
    handle._thread.join(60)
    assert claimed == [False]


def test_a_failure_after_the_budget_hands_over_no_name(monkeypatch, release, capsys):
    monkeypatch.setattr(ipe, "JOIN_BUDGET_S", 0)
    _sources(monkeypatch, release, slow={("crtsh", "example.com")})
    search = ipe.start(_settings(HACKERTARGET_ENABLED=False))
    _until(lambda: _answered(search, subfinder=["example.com"], urlscan=["example.com"]), "the fast sources' answers")
    monkeypatch.setattr(ipe, "finish", mock.Mock(side_effect=RuntimeError("x")))
    found = search.join()
    assert found.names == {} and found.domains == ("example.com",)
    assert "[!][IpNames] Passive search failed (RuntimeError): no name from it this run" in capsys.readouterr().out
    assert ("passive_search", "ip_hostnames") in _gaps()


# ---------------------------------------------------------------------------
# The hook joins it: candidates passive_<src>, the same rule, check 15
# ---------------------------------------------------------------------------

class _Joined:
    def __init__(self, found):
        self.found, self.joins = found, 0

    def join(self):
        self.joins += 1
        return self.found


def _run(ptr=None):
    labels = {T1: "203-0-113-10", T2: "203-0-113-11"}
    return {
        "domain": "ip-targets.cmexpand0000000000000001",
        "metadata": {"ip_mode": True, "expanded_ips": [T1, T2], "ip_to_hostname": dict(labels),
                     "subdomain_filter": [T1, T2, *labels.values()]},
        "subdomains": list(labels.values()),
        "dns": {"domain": {}, "subdomains": {label: {"is_mock": True, "actual_ip": ip, "has_records": True,
                                                     "ips": {"ipv4": [ip], "ipv6": []}, "records": {}}
                                             for ip, label in labels.items()}},
        "ip_hostnames": {"ptr": ptr if ptr is not None else {T1: ["app.example.com"]}},
        "port_scan": {"by_ip": {T1: {"ip": T1, "hostnames": [], "ports": [443]}},
                      "by_host": {T1: {"host": T1, "ip": T1, "ports": [443]}}},
    }


def _hook(run, found, settings=None, dns=None, late=None, monkeypatch=None):
    table = dns if dns is not None else {"app.example.com": [T1], "hidden.example.com": [T1],
                                         "gone.example.com": [FOREIGN], "ghost.example.com": [T1]}
    late = late or mock.Mock(return_value={"http_probe": {"by_url": {}}})
    handle = _Joined(found) if found is not None else None
    block = ih.hostname_step(run, settings or _settings(), resolve=lambda n: list(table.get(n, [])),
                             late_scan=late, passive_search=handle)
    return block, handle, late


@pytest.fixture
def armed(monkeypatch):
    monkeypatch.setattr(ih, "_arm_resolver", lambda canary: True)


def _found(names, wildcard=()):
    return ipe.Found(domains=("example.com",), names=dict(names), answers={}, wildcard_zone=frozenset(wildcard))


def test_passive_names_join_the_candidates_and_pass_the_same_rule(armed):
    found = _found({"hidden.example.com": ("passive_urlscan",), "gone.example.com": ("passive_urlscan",),
                    "app.example.com": ("passive_crtsh",)})
    run = _run()
    block, handle, late = _hook(run, found)
    assert handle.joins == 1
    c = block["candidates"]
    assert {n: x["reason"] for n, x in c.items()} == {
        "app.example.com": "scanned", "hidden.example.com": "scanned", "gone.example.com": "resolves_outside_targets"}
    assert c["hidden.example.com"]["ips_seen"] == [] and c["hidden.example.com"]["seen_on"] == {}
    assert c["hidden.example.com"]["sources"] == ["passive_urlscan"]
    assert c["hidden.example.com"]["org_domain"] == "example.com"
    assert c["hidden.example.com"]["resolves_to_now"] == [T1] and c["hidden.example.com"]["resolves_here"] is True
    assert c["app.example.com"]["ips_seen"] == [T1]
    assert c["app.example.com"]["sources"] == ["passive_crtsh", "ptr"]
    names, pinned = late.call_args.args[1], late.call_args.args[2]
    assert sorted(names) == ["app.example.com", "hidden.example.com"]
    assert pinned["hidden.example.com"] == [T1]
    assert run["metadata"]["ip_mode_hosts"]["hidden.example.com"] == "example.com"
    assert block["summary"]["expansion"] == found.summary()
    # The writer's two halves take a passive-only candidate as it is.
    from graph_db.mixins.recon.ip_hostnames_mixin import _recorded_rows, _scanned_rows
    ((row, seen),) = _recorded_rows({"gone.example.com": c["gone.example.com"]})
    assert row["ips"] == [] and seen == [] and row["sources"] == ["passive_urlscan"]
    scanned = _scanned_rows(run, {"hidden.example.com": c["hidden.example.com"]})
    assert scanned["rows"][0]["sources"] == ["passive_urlscan"]
    assert scanned["edges"] == [{"name": "hidden.example.com", "ip": T1, "record_type": "A"}]


def test_a_wildcard_dropped_passive_name_is_refused_wildcard_zone(armed, monkeypatch):
    calls = []
    real = ih.evaluate
    monkeypatch.setattr(ih, "evaluate", lambda *a, **k: calls.append(k["wildcard_zone"]) or real(*a, **k))
    found = _found({"ghost.example.com": ("passive_crtsh",), "app.example.com": ("passive_crtsh",)},
                   wildcard={"ghost.example.com", "app.example.com"})
    block, _, _ = _hook(_run(), found)
    assert block["candidates"]["ghost.example.com"]["reason"] == "wildcard_zone"
    # A name a target IP showed is scanned whether or not the search ran.
    assert block["candidates"]["app.example.com"]["reason"] == "scanned"
    assert calls == [{"ghost.example.com"}]


def test_without_the_search_check_15_has_nothing(armed, monkeypatch):
    calls = []
    real = ih.evaluate
    monkeypatch.setattr(ih, "evaluate", lambda *a, **k: calls.append(k["wildcard_zone"]) or real(*a, **k))
    block, _, _ = _hook(_run(), None)
    assert calls == [set()] and "expansion" not in block["summary"]


def test_passive_only_names_survive_the_volume_bound_and_count_against_the_run_cap(armed, monkeypatch):
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_RUN", 2)
    found = _found({"b.example.com": ("passive_crtsh",), "c.example.com": ("passive_crtsh",),
                    "d.example.com": ("passive_crtsh",)})
    block, _, _ = _hook(_run(), found, dns={"app.example.com": [T1], "b.example.com": [T1]})
    # The name a target IP showed ranks first, then the passive ones by name.
    assert sorted(block["candidates"]) == ["app.example.com", "b.example.com"]
    assert block["summary"]["truncated"] == 2


def test_a_passive_name_ranks_after_every_observed_name_at_the_run_cut(armed, monkeypatch):
    """Two names Shodan's reverse DNS showed on a target (no live source, no
    date) and one only the search found: the observed ones are kept, though
    the passive name sorts first."""
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_RUN", 2)
    run = _run(ptr={})
    run["shodan"] = {"reverse_dns": {T1: ["yyy.example.com", "zzz.example.com"]}}
    block, _, _ = _hook(run, _found({"aaa.example.com": ("passive_crtsh",)}), dns={})
    assert sorted(block["candidates"]) == ["yyy.example.com", "zzz.example.com"]
    assert block["summary"]["truncated"] == 1


def test_a_name_cut_on_every_ip_stays_when_the_search_found_it(armed, monkeypatch):
    monkeypatch.setattr(ih, "MAX_CANDIDATES_PER_IP", 1)
    found = _found({"zzz.example.com": ("passive_crtsh",)})
    block, _, _ = _hook(_run(ptr={T1: ["app.example.com", "zzz.example.com"]}), found)
    zzz = block["candidates"]["zzz.example.com"]
    assert zzz["ips_seen"] == [] and zzz["sources"] == ["passive_crtsh"]
    assert block["by_ip"][T1]["truncated"] == 1


def test_mode_and_total_lines_say_the_search_ran(armed, capsys):
    found = _found({"hidden.example.com": ("passive_urlscan",), "gone.example.com": ("passive_urlscan",)})
    _hook(_run(), found)
    lines = [line for line in capsys.readouterr().out.splitlines() if "[IpNames]" in line]
    assert lines[0] == "[*][IpNames] Mode: record_filter (include 1, exclude 0, passive expansion on)"
    assert lines[-1] == ("[+][IpNames] Total: 3 found (2 only by the passive search) on 1 of 2 IPs "
                         "→ 2 scanned, 1 recorded; 0 probed by httpx, 0 live")


def test_the_mode_line_says_the_checkbox_is_off(armed, capsys):
    _hook(_run(), None, settings=_settings(IP_HOSTNAME_PASSIVE_EXPAND=False))
    assert "[*][IpNames] Mode: record_filter (include 1, exclude 0, passive expansion off)" in capsys.readouterr().out


def test_a_search_handed_to_another_mode_is_joined_and_ignored(armed):
    found = _found({"hidden.example.com": ("passive_urlscan",)})
    block, handle, _ = _hook(_run(), found, settings=_settings(IP_HOSTNAME_MODE="record_only"))
    assert handle.joins == 1
    assert sorted(block["candidates"]) == ["app.example.com"]
    assert "expansion" not in block["summary"]


def test_add_passive_ignores_what_is_no_passive_name():
    candidates = {}
    ih.add_passive(candidates, {"*.example.com": ("passive_crtsh",), "a.example.com": ("ptr",),
                                "b.example.com": ("passive_crtsh", "ptr"), FOREIGN: ("passive_crtsh",)})
    assert list(candidates) == ["b.example.com"] and candidates["b.example.com"]["sources"] == ["passive_crtsh"]
