"""The takeover scan never hands a tool a name the RoE refuses on its addresses
(R-2, design decision D2).

Subjack and BadDNS are handed names, the Nuclei takeover templates URLs, and
each tool resolves the names itself; the AI classifier then fetches every
candidate's name. A name checked against the RoE by name only could therefore
land on an address inside an RoE IP or CIDR exclusion: a name resolving only
into the range, or a mixed name with one address there. Under IP or CIDR
entries a name is sent only when every address the run knows for it is
allowed; a name with no known address is refused and kept "not checked".

Each test reads what the tools are really handed: the Subjack and BadDNS
target files, the Nuclei takeover target file and the names the AI probe
requests. subprocess, Docker, DNS and HTTP are fakes; the module's collectors,
runners and the admission gate run for real. With no RoE exclusion the inputs
are the ones built without RoE keys at all.

Reserved names and documentation ranges only; no Docker, no network.
"""
from __future__ import annotations

import contextlib
import copy
import json
import re
import subprocess
import sys
from pathlib import Path
from unittest import mock
from urllib.parse import urlparse

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as runner  # noqa: E402
from recon.partial_recon_modules import helpers as partial_helpers  # noqa: E402

APEX, APEX_IP = "example.com", "192.0.2.1"
EXCLUDED_RANGE = "198.51.100.0/24"
LEGACY, LEGACY_IP = "legacy.example.com", "198.51.100.20"           # only an excluded address
MIXED, MIXED_BAD, MIXED_OK = "mixed.example.com", "198.51.100.21", "192.0.2.7"
WWW, WWW_IP = "www.example.com", "192.0.2.6"
GHOST = "ghost.example.com"                                          # dangling CNAME, no address
EXCLUDED_LITERAL, ALLOWED_LITERAL = "198.51.100.30", WWW_IP

ALIVE = [f"https://{WWW}/", f"https://{LEGACY}/", f"https://{MIXED}/login",
         f"http://{EXCLUDED_LITERAL}/", f"http://{ALLOWED_LITERAL}:8080/"]

SETTINGS = {
    "SUBDOMAIN_TAKEOVER_ENABLED": True,
    "SUBJACK_ENABLED": True,
    "NUCLEI_TAKEOVERS_ENABLED": True,
    "BADDNS_ENABLED": True,
    "TAKEOVER_CNAME_VALIDATION_ENABLED": False,
    "TAKEOVER_CERT_VALIDATION_ENABLED": False,
    "TAKEOVER_AI_CLASSIFIER": True,
    "AI_PIPELINE_MODEL": "synthetic-model",
}

NO_ROE = [
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED_RANGE, WWW]},
]


def _roe(*entries):
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _sub(*ips, **extra):
    return {"has_records": True, "ips": {"ipv4": list(ips), "ipv6": []}, **extra}


def _hosts(urls) -> set:
    return {(urlparse(u).hostname or "").lower() for u in urls}


def _roe_gaps(module: str) -> list:
    return [g for g in circuit_breaker.coverage_report().gaps
            if g.get("source") == "roe_excluded" and g.get("module") == module]


def _domain_run() -> dict:
    return {
        "domain": APEX,
        "metadata": {"include_root_domain": True},
        "dns": {
            "domain": {"ips": {"ipv4": [APEX_IP], "ipv6": []}, "has_records": True},
            "subdomains": {
                LEGACY: _sub(LEGACY_IP),
                MIXED: _sub(MIXED_BAD, MIXED_OK),
                WWW: _sub(WWW_IP),
                GHOST: _sub(records={"CNAME": ["ghost-example.github.io."]}),
            },
        },
        "http_probe": {"by_url": {u: {"status_code": 404} for u in ALIVE}},
    }


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})
    yield
    circuit_breaker.reset_registry()
    partial_helpers.set_run_roe({})
    partial_helpers.set_run_ip_targets({})


@pytest.fixture(autouse=True)
def _no_dns():
    """The gate decides on the addresses the run already holds: any lookup
    would be new traffic."""
    def refuse(host, *_a, **_k):
        raise AssertionError(f"unexpected DNS lookup of {host}")
    with mock.patch("socket.getaddrinfo", side_effect=refuse), \
         mock.patch("socket.gethostbyname", side_effect=refuse):
        yield


# --------------------------------------------------------------------------
# The tools, faked at subprocess / Docker / HTTP level
# --------------------------------------------------------------------------

def _completed(cmd, rc=0, stdout="", stderr=""):
    return subprocess.CompletedProcess(cmd, rc, stdout=stdout, stderr=stderr)


@contextlib.contextmanager
def _tools(redirects=None):
    """Fake Subjack, BadDNS, Nuclei and the AI probe's HTTP; yield what each
    was handed.

    Every tool reports each target it was handed as a takeover, so every
    name it saw reaches the AI probe. ``redirects`` maps a Nuclei target URL
    to the ``matched-at`` URL Nuclei reports after following a redirect.
    """
    redirects = redirects or {}
    seen = {"subjack": None, "baddns": None, "nuclei": None, "probe": []}

    def run(cmd, **_kw):
        if cmd[0] == "subjack":
            targets = Path(cmd[cmd.index("-w") + 1]).read_text().split()
            seen["subjack"] = targets
            Path(cmd[cmd.index("-o") + 1]).write_text(json.dumps(
                [{"subdomain": t, "vulnerable": True, "service": "github"} for t in targets]))
            return _completed(cmd)
        if cmd[:3] == ["docker", "image", "inspect"]:
            return _completed(cmd)
        if cmd[:2] == ["docker", "kill"]:
            return _completed(cmd)
        if cmd[:2] == ["docker", "run"]:
            mounts = [a for a in cmd if a.endswith(":/output") or a.endswith(":/work:ro")]
            work_dir = Path(mounts[0].split(":", 1)[0])
            if mounts[0].endswith(":/work:ro"):
                targets = (work_dir / "baddns_targets.txt").read_text().split()
                seen["baddns"] = targets
                return _completed(cmd, stdout="".join(json.dumps(
                    {"target": t, "module": "CNAME", "confidence": "HIGH", "severity": "HIGH",
                     "signature": "github", "description": "dangling"}) + "\n" for t in targets))
            urls = (work_dir / "nuclei_takeover_targets.txt").read_text().split()
            seen["nuclei"] = urls
            (work_dir / "nuclei_takeover_output.jsonl").write_text("".join(json.dumps(
                {"template-id": "github-takeover", "matched-at": redirects.get(u, u),
                 "info": {"name": "github-takeover", "severity": "high", "tags": ["takeover"]}}) + "\n"
                for u in urls))
            return _completed(cmd)
        raise AssertionError(f"unexpected command {cmd[:3]}")

    class _Response:
        status_code = 404
        headers = {}
        text = "There isn't a GitHub Pages site here."

    def get(url, **_kw):
        seen["probe"].append(url)
        return _Response()

    from recon.helpers.ai_planner import takeover_classifier
    with mock.patch.object(runner.shutil, "which", return_value="/usr/local/bin/subjack"), \
         mock.patch.object(runner, "is_docker_installed", return_value=True), \
         mock.patch.object(runner, "is_docker_running", return_value=True), \
         mock.patch.object(runner, "pull_nuclei_docker_image"), \
         mock.patch.object(runner, "ensure_templates_volume"), \
         mock.patch.object(runner, "fix_file_ownership"), \
         mock.patch.object(runner.subprocess, "run", side_effect=run), \
         mock.patch("requests.get", side_effect=get), \
         mock.patch.object(takeover_classifier, "has_third_party_vendor_token", return_value=False), \
         mock.patch.object(takeover_classifier, "classify_takeover_response",
                           return_value={"source": "ai_unavailable"}):
        yield seen


def _capture(settings: dict, recon: dict) -> dict:
    """Run the takeover scan and return what each tool and the AI probe got."""
    with _tools() as seen:
        out = runner.run_subdomain_takeover(recon, settings={**SETTINGS, **settings})
    seen["findings"] = sorted({f["hostname"] for f in out["subdomain_takeover"]["findings"]})
    return seen


def _sent_names(seen: dict) -> set:
    """Every host a tool or the AI probe was handed."""
    return ({*(seen["subjack"] or ()), *(seen["baddns"] or ())}
            | _hosts(seen["nuclei"] or ()) | _hosts(seen["probe"]))


# --------------------------------------------------------------------------
# Full run
# --------------------------------------------------------------------------

def test_no_tool_gets_a_name_resolving_into_an_excluded_range():
    seen = _capture(_roe(EXCLUDED_RANGE), _domain_run())
    # Subjack and BadDNS resolve each name themselves: a name with any
    # excluded address is not sent, nor is a name with no known address.
    assert sorted(seen["subjack"]) == [APEX, WWW]
    assert sorted(seen["baddns"]) == [APEX, WWW]
    # Nuclei resolves a URL's host itself: the same rule, and an excluded
    # address literal is refused too.
    assert sorted(seen["nuclei"]) == sorted([f"http://{ALLOWED_LITERAL}:8080/", f"https://{WWW}/"])
    assert {LEGACY, MIXED, GHOST, LEGACY_IP, MIXED_BAD, EXCLUDED_LITERAL}.isdisjoint(_sent_names(seen))
    # The AI probe fetches only names a tool was allowed to check.
    assert _hosts(seen["probe"]) == {APEX, WWW, ALLOWED_LITERAL}
    assert seen["findings"] == sorted([ALLOWED_LITERAL, APEX, WWW])


def test_the_refusals_are_noted_and_a_name_with_no_address_is_kept_not_checked():
    _capture(_roe(EXCLUDED_RANGE), _domain_run())
    gaps = _roe_gaps("takeover")
    assert gaps, "the refusal is noted under the roe_excluded coverage source"
    assert all(re.fullmatch(r"[a-z0-9_]{1,64}", g["source"]) for g in gaps)
    report = circuit_breaker.coverage_report()
    # Nothing shows the dangling name stays off the range: it is "not
    # checked", never "gone", so its earlier takeover findings are kept.
    assert GHOST in report.skipped_hosts
    assert GHOST in report.keep_hostnames("takeover_scan")
    # An excluded name is a report gap only: the prune treats it as before.
    assert not {LEGACY, MIXED} & set(report.skipped_hosts)


def test_an_excluded_apex_address_refuses_the_apex():
    seen = _capture(_roe(f"{APEX_IP}/32"), _domain_run())
    assert APEX not in seen["subjack"] and APEX not in seen["baddns"]
    assert APEX not in _hosts(seen["probe"])
    # The other names keep their checks; the dangling name has no address.
    assert sorted(seen["subjack"]) == [LEGACY, MIXED, WWW]


def test_name_entries_still_exclude_by_name_only():
    seen = _capture(_roe(WWW), _domain_run())
    assert WWW not in seen["subjack"] and WWW not in _hosts(seen["nuclei"])
    # No IP or CIDR entry: no address check, every other name is checked.
    assert sorted(seen["subjack"]) == [APEX, GHOST, LEGACY, MIXED]
    assert {LEGACY, MIXED} <= _hosts(seen["nuclei"])


@pytest.mark.parametrize("settings", NO_ROE)
def test_the_inputs_are_unchanged_without_an_exclusion(settings):
    baseline = _capture({}, _domain_run())
    circuit_breaker.reset_registry()
    seen = _capture(settings, _domain_run())
    for key in ("subjack", "baddns", "nuclei"):
        assert sorted(seen[key]) == sorted(baseline[key])
    assert sorted(seen["probe"]) == sorted(baseline["probe"])
    assert sorted(baseline["subjack"]) == [APEX, GHOST, LEGACY, MIXED, WWW]
    assert sorted(baseline["nuclei"]) == sorted(ALIVE)
    assert not _roe_gaps("takeover")


REDIRECTED = "elsewhere.example.org"


@pytest.mark.parametrize("settings", [{}, _roe(EXCLUDED_RANGE)])
@pytest.mark.parametrize("matched_at", [f"https://{REDIRECTED}/login", "http://198.51.100.50/"])
def test_the_ai_probe_never_fetches_a_host_the_run_did_not_admit(settings, matched_at):
    """Nuclei follows redirects and names its finding after the URL that
    matched, which can be a host no layer was handed."""
    with _tools(redirects={f"https://{WWW}/": matched_at}) as seen:
        out = runner.run_subdomain_takeover(_domain_run(), settings={**SETTINGS, **settings})
    stray = urlparse(matched_at).hostname
    assert stray not in _hosts(seen["probe"])
    # The finding stands on its static evidence; only the extra request is not sent.
    assert stray in {f["hostname"] for f in out["subdomain_takeover"]["findings"]}
    assert WWW in _hosts(seen["probe"])


def test_ip_mode_keeps_its_own_rules_under_an_exclusion():
    """IP mode's names are kept by GROUP 1 only when every forward address is
    a target, and the targets are RoE-filtered: the collectors keep P0b's
    behaviour, with or without an RoE IP entry."""
    run = _domain_run()
    run["domain"] = "ip-targets.example"
    run["metadata"].update(ip_mode=True, expanded_ips=[WWW_IP, MIXED_OK])
    run["dns"] = {"domain": {}, "subdomains": {WWW: _sub(WWW_IP), "192-0-2-7": _sub(MIXED_OK)}}
    run["http_probe"] = {"by_url": {f"https://{WWW}/": {"status_code": 200},
                                    f"http://{MIXED_OK}/": {"status_code": 200}}}
    ip_settings = {"IP_MODE": True}
    baseline = (runner._collect_subdomains(copy.deepcopy(run), ip_settings),
                runner._collect_alive_urls(copy.deepcopy(run), ip_settings))
    for settings in (_roe(EXCLUDED_RANGE), _roe(f"{LEGACY_IP}/32")):
        both = {**ip_settings, **settings}
        assert runner._collect_subdomains(copy.deepcopy(run), both) == baseline[0]
        assert runner._collect_alive_urls(copy.deepcopy(run), both) == baseline[1]
    assert baseline == ([WWW], [f"http://{MIXED_OK}/", f"https://{WWW}/"])


# --------------------------------------------------------------------------
# Partial takeover: the vuln-scan graph builder, typed names, the same scan
# --------------------------------------------------------------------------

# (subdomain, address) forward-DNS rows the graph holds from an earlier run.
GRAPH_DNS = [(LEGACY, LEGACY_IP), (MIXED, MIXED_BAD), (MIXED, MIXED_OK), (WWW, WWW_IP)]
GRAPH_SUBDOMAINS = [LEGACY, MIXED, WWW]
GRAPH_BASEURLS = [f"https://{WWW}", f"https://{LEGACY}", f"https://{MIXED}"]
TYPED, TYPED_IP = "typed.example.com", "198.51.100.40"


class _Rows(list):
    def single(self):
        return self[0] if self else None


def _address_row(address):
    return {"address": address, "ip": address, "version": "IPv4", "is_cdn": False,
            "cdn_name": None, "asn": None, "ports": []}


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **_params):
        rows = _Rows()
        if "AS host, i.address AS address" in cypher:
            rows.extend({"host": s, "address": a} for s, a in [(APEX, APEX_IP), *GRAPH_DNS])
        elif "$apex_roots" in cypher:
            rows.append({"root": APEX, **_address_row(APEX_IP)})
        elif re.search(r"AS sub\b", cypher):
            rows.extend({"root": APEX, "sub": s} for s in GRAPH_SUBDOMAINS)
        elif "collect(DISTINCT s.name)" in cypher:
            rows.append({"subdomains": list(GRAPH_SUBDOMAINS)})
        elif "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            rows.extend({"root": APEX, "subdomain": s, **_address_row(a)} for s, a in GRAPH_DNS)
        elif "(e:Endpoint)" in cypher or "USES_TECHNOLOGY" in cypher:
            pass
        elif "MATCH (b:BaseURL" in cypher:
            rows.extend({"url": u, "host": urlparse(u).hostname, "status_code": 404,
                         "content_type": "text/html", "is_cdn": False, "cdn": None, "asn": None}
                        for u in GRAPH_BASEURLS)
        return rows


class _Client:
    def __init__(self, *_a, **_k):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def verify_connection(self):
        return True

    @property
    def driver(self):
        driver = mock.MagicMock()
        driver.session.side_effect = lambda **_k: _Session()
        return driver

    def update_graph_from_subdomain_takeover(self, **_k):
        return {}


def _partial_capture(settings, monkeypatch) -> dict:
    from recon.partial_recon_modules import vulnerability_scanning
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr(vulnerability_scanning, "_resolve_hostname",
                        lambda host: {"ipv4": [TYPED_IP] if host == TYPED else [], "ipv6": []})
    run_settings = {"SUBDOMAIN_LIST": ["."], "BADDNS_ENABLED": False, **SETTINGS,
                    "TAKEOVER_AI_CLASSIFIER": False, **settings}
    # What partial_recon._prepare_scope does before any module runs.
    partial_helpers.set_run_roe(run_settings)
    config = {"_settings": run_settings, "domains": [APEX], "domain": APEX,
              "user_targets": {"subdomains": [TYPED]}}
    with _tools() as seen:
        vulnerability_scanning.run_subdomain_takeover_partial(config)
    return seen


def test_partial_takeover_never_gets_a_typed_name_resolving_into_an_excluded_range(monkeypatch):
    seen = _partial_capture(_roe(EXCLUDED_RANGE), monkeypatch)
    assert TYPED not in seen["subjack"]
    # The builder keeps an excluded address in its DNS block, so a name whose
    # only address is excluded is refused for it too.
    assert LEGACY not in seen["subjack"] and LEGACY not in _hosts(seen["nuclei"])
    assert WWW in seen["subjack"] and WWW in _hosts(seen["nuclei"])
    assert _roe_gaps("takeover")


@pytest.mark.parametrize("settings", NO_ROE)
def test_partial_takeover_inputs_are_unchanged_without_an_exclusion(settings, monkeypatch):
    baseline = _partial_capture({}, monkeypatch)
    circuit_breaker.reset_registry()
    seen = _partial_capture(settings, monkeypatch)
    assert sorted(seen["subjack"]) == sorted(baseline["subjack"])
    assert sorted(seen["nuclei"]) == sorted(baseline["nuclei"])
    assert {TYPED, LEGACY, MIXED, WWW} <= set(baseline["subjack"])


def test_partial_takeover_never_gets_a_graph_name_with_one_excluded_address(monkeypatch):
    seen = _partial_capture(_roe(EXCLUDED_RANGE), monkeypatch)
    assert MIXED not in seen["subjack"]
    assert MIXED not in _hosts(seen["nuclei"])
