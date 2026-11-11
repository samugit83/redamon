"""Katana, Hakrawler and the form fetcher never reach a host the run refused
through a redirect or a sibling-subdomain link (R-2, design decision D2).

Proved on the images the pipeline runs (katana v1.8.0, jauderho/hakrawler)
against two loopback servers in a ``--network none`` container, the seed
answering 302 into the excluded one:

- katana follows a redirect inside its HTTP client, before any scope check:
  with ``-fs fqdn``, with ``-cos <excluded>`` and with ``-e <excluded>`` the
  excluded host was requested; only ``-dr`` stopped the hop;
- hakrawler keeps to the seed's host and its same-host redirects, but with
  ``-subs`` it follows links and redirects into every subdomain of the seed;
- the form fetcher (urllib) follows any redirect.

So when the run admits targets one by one (RoE exclusions, or IP mode's target
list), katana gets ``-dr``, hakrawler loses ``-subs`` and the form fetcher
follows same-host redirects only. With no exclusion in force every argv and
every fetch is the one built before.

Only Docker, the tool processes and Neo4j are replaced; the form-fetcher tests
use real servers on 127.0.0.1 and 127.0.0.2. Reserved names and RFC 5737
addresses otherwise.
"""
from __future__ import annotations

import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.resource_enum import hakrawler_helpers, katana_helpers  # noqa: E402

TARGET, EXCLUDED = "192.0.2.20", "192.0.2.21"
HOST, SIBLING = "www.example.com", "vendor.example.com"

#: Every way an exclusion is written: an address, a range, a name.
EXCLUSIONS = [EXCLUDED, "192.0.2.0/25", SIBLING]

#: An admission context that is not active: RoE on with nothing listed, or
#: entries listed with RoE off, or no settings at all.
INACTIVE = [
    None,
    {},
    {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": []},
    {"ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [EXCLUDED, SIBLING]},
]


def _roe(*entries) -> dict:
    return {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": list(entries)}


def _ip_mode(*targets) -> dict:
    return {"metadata": {"ip_mode": True, "expanded_ips": list(targets)}}


@pytest.fixture(autouse=True)
def _fresh_run():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


# --------------------------------------------------------------------------
# Katana: the argv run_katana_crawler builds
# --------------------------------------------------------------------------

def _fake_popen(katana: list, hakrawler: list, lines=()):
    """One Popen for both tools: they share the subprocess module, so a second
    patch of Popen would replace the first. Routed by the image in the argv."""
    def fake_popen(cmd, *_a, **_k):
        proc = MagicMock()
        proc.poll.return_value = 0
        proc.returncode = 0
        proc.wait.return_value = 0
        if "projectdiscovery/katana:latest" in cmd:
            katana.append(list(cmd))
            proc.stdout.readline.side_effect = [line + "\n" for line in lines] + [""]
            proc.stderr.read.return_value = ""
        else:
            hakrawler.append(list(cmd))
            proc.stdout.readline.return_value = ""
        return proc
    return fake_popen


def _tool_patches(katana: list, hakrawler: list, lines=()):
    return [
        mock.patch.object(katana_helpers.subprocess, "Popen", side_effect=_fake_popen(katana, hakrawler, lines)),
        mock.patch.object(katana_helpers.select, "select", side_effect=lambda r, w, x, t: (r, [], [])),
        mock.patch("helpers.proxy_routing.get_capture_routing", return_value=(None, None), create=True),
    ]


def _katana_cmd(**kwargs) -> list:
    commands: list = []
    patches = _tool_patches(commands, [])
    for p in patches:
        p.start()
    try:
        katana_helpers.run_katana_crawler(
            [f"https://{HOST}"], "projectdiscovery/katana:latest", 2, 100, 10, 30,
            False, False, {HOST}, [], [], **kwargs)
    finally:
        for p in patches:
            p.stop()
    assert len(commands) == 1
    return commands[0]


#: The argv katana got before this fix, flag for flag (test_katana_field_scope).
KATANA_ARGV = [
    "docker", "run", "--rm", "--net=host", "-v", "/tmp/redamon:/tmp/redamon",
    "projectdiscovery/katana:latest",
    "-list", "/tmp/redamon/katana_targets_deadbeef.txt",
    "-d", "2", "-silent", "-nc", "-rl", "10", "-p", "5", "-c", "10",
    "-timeout", "30", "-crawl-duration", "30s", "-fs", "fqdn",
    "-r", "192.0.2.53",
]


def _pinned_katana_cmd(**kwargs) -> list:
    with mock.patch.object(katana_helpers, "resolver_args", return_value=["-r", "192.0.2.53"]), \
         mock.patch.object(katana_helpers.uuid, "uuid4", return_value=MagicMock(hex="deadbeefcafe")):
        cmd = _katana_cmd(**kwargs)
    i = cmd.index("--name")
    assert cmd[i + 1].startswith("katana-")
    del cmd[i:i + 2]
    return cmd


@pytest.mark.parametrize("entry", EXCLUSIONS)
def test_katana_follows_no_redirect_under_an_roe_exclusion(entry):
    cmd = _katana_cmd(settings=_roe(entry))
    assert cmd.count("-dr") == 1


def test_katana_follows_no_redirect_in_ip_mode():
    cmd = _katana_cmd(settings={}, recon_data=_ip_mode(TARGET))
    assert cmd.count("-dr") == 1


def test_katana_reads_the_roe_a_partial_builder_stamped():
    # Partial graph builders carry the RoE in metadata.roe for readers that get
    # no RoE keys in their settings.
    cmd = _katana_cmd(settings={}, recon_data={"metadata": {"roe": _roe(EXCLUDED)}})
    assert cmd.count("-dr") == 1


def test_katana_with_redirects_off_keeps_the_rest_of_its_argv():
    cmd = _pinned_katana_cmd(settings=_roe(EXCLUDED))
    cmd.remove("-dr")
    assert cmd == KATANA_ARGV


@pytest.mark.parametrize("settings", INACTIVE)
def test_katana_argv_is_unchanged_without_an_exclusion(settings):
    assert _pinned_katana_cmd(settings=settings) == KATANA_ARGV


def test_katana_argv_is_unchanged_when_called_without_the_run():
    assert _pinned_katana_cmd() == KATANA_ARGV


# --------------------------------------------------------------------------
# Hakrawler: the argv _crawl_single_url builds
# --------------------------------------------------------------------------

def _hakrawler_cmds(include_subs=True, **kwargs) -> list:
    commands: list = []
    patches = _tool_patches([], commands)
    for p in patches:
        p.start()
    try:
        hakrawler_helpers.run_hakrawler_crawler(
            [f"https://{HOST}"], "jauderho/hakrawler:latest", 2, 5, 30, 100,
            include_subs, True, {HOST}, [], [], 1, **kwargs)
    finally:
        for p in patches:
            p.stop()
    assert len(commands) == 1
    cmd = commands[0]
    i = cmd.index("--name")
    assert cmd[i + 1].startswith("hakrawler-")
    del cmd[i:i + 2]
    return cmd


HAKRAWLER_ARGV = ["docker", "run", "--rm", "--net=host", "-i", "jauderho/hakrawler:latest",
                  "-d", "2", "-t", "5", "-timeout", "30", "-u", "-insecure", "-subs"]


@pytest.mark.parametrize("entry", EXCLUSIONS)
def test_hakrawler_crawls_no_sibling_subdomain_under_an_roe_exclusion(entry):
    assert _hakrawler_cmds(settings=_roe(entry)) == HAKRAWLER_ARGV[:-1]


def test_hakrawler_crawls_no_sibling_subdomain_in_ip_mode():
    assert _hakrawler_cmds(settings={}, recon_data=_ip_mode(TARGET)) == HAKRAWLER_ARGV[:-1]


def test_hakrawler_keeps_subs_off_when_the_operator_turned_it_off():
    assert "-subs" not in _hakrawler_cmds(include_subs=False, settings={})


@pytest.mark.parametrize("settings", INACTIVE)
def test_hakrawler_argv_is_unchanged_without_an_exclusion(settings):
    assert _hakrawler_cmds(settings=settings) == HAKRAWLER_ARGV


def test_hakrawler_argv_is_unchanged_when_called_without_the_run():
    assert _hakrawler_cmds() == HAKRAWLER_ARGV


# --------------------------------------------------------------------------
# The form fetcher, against real loopback servers
# --------------------------------------------------------------------------

FORM = b"<html><body><form action='/%s' method='post'><input name='%s'></form></body></html>"


class _Lab:
    """127.0.0.1 is the admitted host, 127.0.0.2 the one a redirect names."""

    def __init__(self):
        self.vendor_paths: list = []
        lab = self

        class Seed(BaseHTTPRequestHandler):
            def log_message(self, *_a):
                pass

            def do_GET(self):
                if self.path == "/go":
                    self._send(302, b"", {"Location": f"http://127.0.0.2:{lab.vendor_port}/landing"})
                elif self.path == "/same":
                    self._send(302, b"", {"Location": "/moved"})
                elif self.path == "/moved":
                    self._send(200, FORM % (b"own", b"own_field"), {"Content-Type": "text/html"})
                else:
                    self._send(404, b"", {})

            def _send(self, code, body, headers):
                self.send_response(code)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        class Vendor(Seed):
            def do_GET(self):
                lab.vendor_paths.append(self.path)
                self._send(200, FORM % (b"idp", b"idp_field"), {"Content-Type": "text/html"})

        try:
            self.vendor = ThreadingHTTPServer(("127.0.0.2", 0), Vendor)
        except OSError as exc:
            pytest.skip(f"cannot bind 127.0.0.2 here: {exc}")
        self.seed = ThreadingHTTPServer(("127.0.0.1", 0), Seed)
        self.vendor_port = self.vendor.server_address[1]
        self.seed_port = self.seed.server_address[1]
        for server in (self.seed, self.vendor):
            threading.Thread(target=server.serve_forever, daemon=True).start()

    def url(self, path: str) -> str:
        return f"http://127.0.0.1:{self.seed_port}{path}"

    def close(self):
        for server in (self.seed, self.vendor):
            server.shutdown()
            server.server_close()


@pytest.fixture
def lab():
    socket.setdefaulttimeout(5)
    lab = _Lab()
    yield lab
    lab.close()
    socket.setdefaulttimeout(None)


def _form_fields(forms) -> set:
    return {i.get("name") for f in forms for i in f.get("inputs", [])}


@pytest.mark.parametrize("run", [
    {"settings": _roe("127.0.0.2")},
    {"settings": _roe("192.0.2.0/24")},   # any exclusion: the hop could land on it
    {"settings": {}, "recon_data": _ip_mode("127.0.0.1")},
], ids=["roe_ip", "roe_unrelated_range", "ip_mode"])
def test_the_form_fetcher_follows_no_redirect_off_the_host(lab, run):
    forms = katana_helpers.fetch_forms_from_urls([lab.url("/go"), lab.url("/same")], **run)
    assert lab.vendor_paths == []
    # A same-host redirect is still followed.
    assert _form_fields(forms) == {"own_field"}


@pytest.mark.parametrize("settings", INACTIVE)
def test_the_form_fetcher_is_unchanged_without_an_exclusion(lab, settings):
    forms = katana_helpers.fetch_forms_from_urls([lab.url("/go"), lab.url("/same")], settings=settings)
    assert lab.vendor_paths == ["/landing"]
    assert _form_fields(forms) == {"own_field", "idp_field"}


def test_the_form_fetcher_is_unchanged_when_called_without_the_run(lab):
    forms = katana_helpers.fetch_forms_from_urls([lab.url("/go"), lab.url("/same")])
    assert lab.vendor_paths == ["/landing"]
    assert _form_fields(forms) == {"own_field", "idp_field"}


# --------------------------------------------------------------------------
# The pipeline hands the run to the crawlers: full run_resource_enum
# --------------------------------------------------------------------------

CRAWL = {
    "KATANA_ENABLED": True, "KATANA_TIMEOUT": 30, "HAKRAWLER_ENABLED": True,
    "HAKRAWLER_INCLUDE_SUBS": True, "HAKRAWLER_PARALLELISM": 1,
    "GAU_ENABLED": False, "PARAMSPIDER_ENABLED": False, "KITERUNNER_ENABLED": False,
    "JSLUICE_ENABLED": False, "FFUF_ENABLED": False, "ARJUN_ENABLED": False,
    "ZAP_AJAX_SPIDER_ENABLED": False, "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": False,
    "OPENAPI_ENABLED": False,
}


def _domain_recon() -> dict:
    return {
        "domain": "example.com",
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {HOST: {"has_records": True, "ips": {"ipv4": ["192.0.2.6"], "ipv6": []}}}},
        "http_probe": {"by_url": {f"https://{HOST}": {"url": f"https://{HOST}", "status_code": 200}}},
    }


def _ip_recon() -> dict:
    return {
        "domain": "ip-targets.example",
        "metadata": {"ip_mode": True, "expanded_ips": [TARGET]},
        "http_probe": {"by_url": {f"http://{TARGET}": {"url": f"http://{TARGET}", "status_code": 200}}},
    }


def _full_run(recon: dict, settings: dict):
    """The katana argv, the hakrawler argvs and the run the form fetcher got."""
    import recon.main_recon_modules.resource_enum as re_mod
    from recon.helpers.resource_enum import endpoint_helpers
    katana_cmds: list = []
    hakrawler_cmds: list = []
    form_runs: list = []
    seed = next(iter(recon["http_probe"]["by_url"]))

    def forms(urls, *_a, **kwargs):
        form_runs.append(kwargs)
        return []

    patches = _tool_patches(katana_cmds, hakrawler_cmds, lines=[f"{seed}/login"]) + [
        mock.patch.object(endpoint_helpers, "fetch_forms_from_urls", side_effect=forms),
        mock.patch.object(re_mod, "pull_katana_docker_image", return_value=True),
        mock.patch.object(re_mod, "pull_hakrawler_docker_image", return_value=True),
        mock.patch.object(re_mod, "is_docker_installed", return_value=True),
        mock.patch.object(re_mod, "is_docker_running", return_value=True),
    ]
    for p in patches:
        p.start()
    try:
        re_mod.run_resource_enum(recon, settings={**CRAWL, **settings})
    finally:
        for p in patches:
            p.stop()
    assert len(katana_cmds) == 1, "Katana never ran"
    assert hakrawler_cmds, "Hakrawler never ran"
    assert form_runs, "the form fetcher never ran"
    return katana_cmds[0], hakrawler_cmds, form_runs


def _contained(form_run: dict) -> bool:
    return katana_helpers.redirects_contained(form_run.get("settings"), form_run.get("recon_data"))


def test_a_full_ip_mode_run_with_an_excluded_neighbour_keeps_every_crawler_on_its_target():
    """The FP lab's R14J-05 case: .20 answers 302 into the RoE-excluded .21."""
    katana, hakrawler, form_runs = _full_run(_ip_recon(), _roe(EXCLUDED))
    assert "-dr" in katana
    assert all("-subs" not in cmd for cmd in hakrawler)
    assert all(_contained(run) for run in form_runs)


def test_a_full_domain_run_with_an_exclusion_keeps_every_crawler_on_its_seeds():
    katana, hakrawler, form_runs = _full_run(_domain_recon(), _roe(SIBLING))
    assert "-dr" in katana
    assert all("-subs" not in cmd for cmd in hakrawler)
    assert all(_contained(run) for run in form_runs)


@pytest.mark.parametrize("settings", INACTIVE[1:])
def test_a_full_domain_run_without_an_exclusion_crawls_as_before(settings):
    katana, hakrawler, form_runs = _full_run(_domain_recon(), settings)
    assert "-dr" not in katana
    assert all("-subs" in cmd for cmd in hakrawler)
    assert not any(_contained(run) for run in form_runs)


# --------------------------------------------------------------------------
# Partial recon: run_katana / run_hakrawler
# --------------------------------------------------------------------------

@pytest.fixture
def partial(monkeypatch):
    """Run a partial crawler on graph-built seeds; return its argvs and form runs."""
    import recon.helpers.resource_enum as resource_enum
    from recon.helpers.resource_enum import endpoint_helpers
    from recon.partial_recon_modules import web_crawling

    client = MagicMock()
    client.__enter__.return_value = client
    client.verify_connection.return_value = True
    client.update_graph_from_resource_enum.return_value = {}
    graph_db = MagicMock()
    graph_db.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", graph_db)
    monkeypatch.setattr(resource_enum, "pull_katana_docker_image", lambda *_a, **_k: True)
    monkeypatch.setattr(resource_enum, "pull_hakrawler_docker_image", lambda *_a, **_k: True)

    def run(entry: str, settings: dict):
        katana: list = []
        hakrawler: list = []
        form_runs: list = []

        def forms(urls, *_a, **kwargs):
            form_runs.append(kwargs)
            return []

        def graph_seeds(roots, *_a, **_k):
            return {"domain": roots[0], "domains": list(roots), "subdomains": [HOST],
                    "http_probe": {"by_url": {f"https://{HOST}": {"url": f"https://{HOST}",
                                                                  "status_code": 200}}}}

        monkeypatch.setattr(web_crawling, "_build_http_probe_data_from_graph", graph_seeds)
        monkeypatch.setattr(endpoint_helpers, "fetch_forms_from_urls", forms)
        patches = _tool_patches(katana, hakrawler, lines=[f"https://{HOST}/login"])
        for p in patches:
            p.start()
        try:
            getattr(web_crawling, entry)({
                "_settings": {"HAKRAWLER_INCLUDE_SUBS": True, "HAKRAWLER_PARALLELISM": 1,
                              "KATANA_TIMEOUT": 30, **settings},
                "domains": ["example.com"], "domain": "example.com",
            })
        finally:
            for p in patches:
                p.stop()
        commands = katana if entry == "run_katana" else hakrawler
        assert commands and not (katana and hakrawler), f"{entry} did not start its own tool only"
        return commands, form_runs

    return run


def test_partial_katana_follows_no_redirect_under_an_exclusion(partial):
    commands, form_runs = partial("run_katana", _roe(SIBLING))
    assert all("-dr" in cmd for cmd in commands)
    assert form_runs and all(_contained(run) for run in form_runs)


def test_partial_hakrawler_crawls_no_sibling_under_an_exclusion(partial):
    commands, form_runs = partial("run_hakrawler", _roe(SIBLING))
    assert all("-subs" not in cmd for cmd in commands)
    assert form_runs and all(_contained(run) for run in form_runs)


@pytest.mark.parametrize("settings", INACTIVE[1:])
def test_partial_crawlers_run_as_before_without_an_exclusion(partial, settings):
    katana, katana_forms = partial("run_katana", settings)
    hakrawler, hakrawler_forms = partial("run_hakrawler", settings)
    assert all("-dr" not in cmd for cmd in katana)
    assert all("-subs" in cmd for cmd in hakrawler)
    assert not any(_contained(run) for run in katana_forms + hakrawler_forms)
