"""Partial recon follows the IP hostname mode.

A full IP-mode run selects the names it scans with the hostname policy and
writes them as Subdomain {source: 'ip_hostname_selection', reason 'scanned'}
under their org Domain; every other name it saw is an ExternalDomain with
SEEN_ON evidence. A partial run never trusts those reasons on their own: at
its start (partial_recon._prepare_scope) it computes S once, the names the
selection rule admits NOW with the project's current policy, live DNS, the
RoE, the hard guardrail and the cap, and every reader of the run keeps a name
only when it is in S:

  - ip_only / record_only: S is empty; a typed name is refused; the name-only
    tools (Gau, ParamSpider, SubdomainTakeover) are refused;
  - record_filter / scan_all: the scanned Subdomains and the recorded names
    the rule selects now, plus the typed names it selects. A name the
    narrowing marker set out_of_policy is never in S (D-19); a name that moved
    off the targets is dropped at run time.

The builders keep the target labels always and a real name only in S; the URL
scope keeps a host in T or S; a typed name attaches to its org Domain, never to
the synthetic root. Neo4j, DNS and the tools are fakes.

Documentation addresses (RFC 5737, RFC 3849) and reserved names only.

Run: ./redamon.sh test unit (recon section), or one file in the recon image
(06_testing.md §1.2).
"""
import sys
from pathlib import Path
from unittest import mock

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers import circuit_breaker  # noqa: E402
from recon.partial_recon_modules import graph_builders as gb  # noqa: E402
from recon.partial_recon_modules import helpers  # noqa: E402
from recon.partial_recon_modules import ip_hostname_scope as hs  # noqa: E402

PID = "cmipnamespartial0000000001"
ROOT = f"ip-targets.{PID}"
T1, T2, V6 = "203.0.113.1", "203.0.113.2", "2001:db8::1"
FOREIGN = "198.51.100.7"
LABEL = "203-0-113-1"
APP, API, SHOP = "app.example.com", "api.example.com", "shop.example.net"
OLD_PTR = "host1.provider.example"     # a pre-P3 PTR Subdomain under the synthetic root

BASE = {"IP_MODE": True, "TARGET_IPS": [T1, T2, V6], "ROE_ENABLED": False, "ROE_EXCLUDED_HOSTS": [],
        "DOMAIN_BATCH_MODE": False, "TARGET_DOMAIN": "", "DNS_ENABLED": True,
        "IP_HOSTNAME_MAX_SCANNED": 100, "IP_HOSTNAME_INCLUDE": ["*.example.com"], "IP_HOSTNAME_EXCLUDE": []}


def _settings(mode, **extra):
    return dict(BASE, IP_HOSTNAME_MODE=mode, **extra)


@pytest.fixture(autouse=True)
def _fresh_run(monkeypatch):
    circuit_breaker.reset_registry()
    helpers.set_run_ip_targets({})
    helpers.set_run_roe({})
    # The canary is a real DNS lookup: the rule only needs to hear "up".
    monkeypatch.setattr("recon.helpers.ip_hostnames._arm_resolver", lambda _canary: True)
    yield
    helpers.set_run_ip_targets({})
    helpers.set_run_roe({})
    circuit_breaker.reset_registry()


class _Resolver:
    """resolve(name) -> answer, counting the lookups."""

    def __init__(self, table):
        self.table, self.calls = dict(table), []

    def __call__(self, name):
        self.calls.append(name)
        answer = self.table.get(name)
        if isinstance(answer, Exception):
            raise answer
        return list(answer or [])


def _graph(scanned=None, recorded=None, excluded=(), attribution=None):
    return {"scanned": dict(scanned or {}), "recorded": dict(recorded or {}),
            "excluded": set(excluded), "attribution": attribution}


def _scope(mode, graph=None, table=None, config=None, monkeypatch=None, **extra):
    settings = _settings(mode, **extra)
    helpers.set_run_ip_targets(settings)
    helpers.set_run_roe(settings)
    reads = []
    monkeypatch.setattr(hs, "read_candidates",
                        lambda uid, pid: reads.append((uid, pid)) or (graph if graph is not None else _graph()))
    written = []
    monkeypatch.setattr(hs, "_record_typed", lambda names, *a, **k: written.append(sorted(names)))
    resolver = _Resolver(table or {})
    cfg = config if config is not None else {"domains": [ROOT]}
    refused = hs.run_hostname_scope(cfg, settings, "u1", PID, resolve=resolver)
    return refused, resolver, reads, written, cfg


# ---------------------------------------------------------------------------
# S per mode, computed once with the current policy
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("mode", ["ip_only", "record_only"])
def test_a_recording_mode_has_no_hostname_target_and_reads_nothing(mode, monkeypatch, capsys):
    refused, resolver, reads, _, cfg = _scope(
        mode, _graph(scanned={APP: [T1]}), {APP: [T1]}, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {}
    assert refused == {} and resolver.calls == [] and reads == []
    assert cfg["ip_hostname_scope"] == {"mode": mode, "names": {}, "refused": {}}
    assert "no hostname is a target" in capsys.readouterr().out


def test_record_filter_keeps_the_scanned_names_the_current_policy_admits(monkeypatch):
    graph = _graph(scanned={APP: [T1], SHOP: [T2]}, recorded={API: {"ips": [T2], "reason": "filter_no_match"}})
    refused, resolver, reads, _, cfg = _scope(
        "record_filter", graph, {APP: [T1], API: [T2], SHOP: [T2]}, monkeypatch=monkeypatch)
    # SHOP was scanned under an older policy; *.example.com no longer admits it.
    assert helpers.run_ip_hostnames() == {APP: "example.com", API: "example.com"}
    assert reads == [("u1", PID)]
    assert sorted(resolver.calls) == [API, APP]          # once each, only names past the filter
    assert refused == {f"hostname {SHOP}": "scanned before, not now (filter_no_match)"}
    assert cfg["ip_hostname_scope"] == {"mode": "record_filter", "names": helpers.run_ip_hostnames(),
                                        "refused": refused}


def test_an_out_of_policy_name_is_never_in_s_even_when_the_policy_admits_it(monkeypatch):
    graph = _graph(recorded={APP: {"ips": [T1], "reason": "filter_no_match"}}, excluded={APP})
    _scope("record_filter", graph, {APP: [T1]}, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {}


def test_a_moved_name_is_dropped_at_run_time(monkeypatch):
    refused, *_ = _scope("record_filter", _graph(scanned={APP: [T1]}), {APP: [T1, FOREIGN]},
                         monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {}
    assert refused == {f"hostname {APP}": "scanned before, not now (resolves_outside_targets)"}


def test_a_private_target_is_allowed(monkeypatch):
    settings = dict(TARGET_IPS=["10.0.0.5"])
    _scope("record_filter", _graph(scanned={APP: ["10.0.0.5"]}), {APP: ["10.0.0.5"]},
           monkeypatch=monkeypatch, **settings)
    assert helpers.run_ip_hostnames() == {APP: "example.com"}


def test_the_roe_the_guardrail_and_the_cap_apply(monkeypatch):
    names = {"a.example.com": [T1], "b.example.com": [T1], "c.example.com": [T1], "www.example.gov": [T1]}
    refused, resolver, *_ = _scope(
        "scan_all", _graph(scanned=names, attribution={T1: ("dedicated", []), T2: ("dedicated", []),
                                                       V6: ("dedicated", [])}),
        names, monkeypatch=monkeypatch, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["a.example.com"],
        IP_HOSTNAME_MAX_SCANNED=1)
    assert helpers.run_ip_hostnames() == {"b.example.com": "example.com"}
    assert refused["hostname a.example.com"].endswith("(roe_excluded)")
    assert refused["hostname www.example.gov"].endswith("(hard_blocked)")
    assert refused["hostname c.example.com"].endswith("(cap_reached)")
    assert "a.example.com" not in resolver.calls and "www.example.gov" not in resolver.calls


def test_scan_all_refuses_names_without_attribution_and_on_a_shared_edge(monkeypatch):
    graph = _graph(scanned={APP: [T1], API: [T2]},
                   attribution={T1: ("shared_edge", []), T2: ("dedicated", []), V6: ("dedicated", [])})
    refused, *_ = _scope("scan_all", graph, {APP: [T1], API: [T2]}, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {API: "example.com"}
    assert refused[f"hostname {APP}"].endswith("(shared_edge_ip)")
    helpers.set_run_ip_hostnames({})
    refused, *_ = _scope("scan_all", _graph(scanned={APP: [T1]}), {APP: [T1]}, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {}
    assert refused[f"hostname {APP}"].endswith("(attribution_unavailable)")


def test_dns_off_and_a_graph_that_cannot_be_read_select_nothing(monkeypatch, capsys):
    refused, resolver, *_ = _scope("record_filter", _graph(scanned={APP: [T1]}), {APP: [T1]},
                                   monkeypatch=monkeypatch, DNS_ENABLED=False)
    assert helpers.run_ip_hostnames() == {} and resolver.calls == []
    assert refused[f"hostname {APP}"].endswith("(dns_disabled)")
    monkeypatch.setattr(hs, "read_candidates", lambda *_a: None)
    hs.run_hostname_scope({"domains": [ROOT]}, _settings("record_filter"), "u1", PID,
                          resolve=_Resolver({APP: [T1]}))
    assert helpers.run_ip_hostnames() == {}


def test_prepare_scope_computes_s_once_for_the_run(monkeypatch):
    import recon.partial_recon as pr
    calls = []
    monkeypatch.setattr(hs, "run_hostname_scope",
                        lambda cfg, settings, uid, pid, **_k: calls.append(pid) or {"hostname x.example.com": "why"})
    monkeypatch.setenv("USER_ID", "u1")
    cfg = {"tool_id": "Httpx", "domains": [ROOT]}
    refused = pr._prepare_scope(cfg, _settings("record_filter"), PID)
    assert calls == [PID]
    assert refused == {"hostname x.example.com": "why"}
    assert cfg["ip_hostname_mode"] == "record_filter"
    pr._prepare_scope({"tool_id": "Httpx", "domains": ["example.com"]},
                      {"IP_MODE": False, "TARGET_DOMAIN": "example.com", "SUBDOMAIN_LIST": ["."]}, PID)
    assert calls == [PID]
    assert helpers.run_ip_hostnames() == {}


def test_no_partial_run_resolves_a_name_unless_ip_mode_scans_names(monkeypatch):
    """Only an IP-mode run in record_filter / scan_all with a name to judge
    looks anything up: a domain run, IP only and Record hostnames never reach
    the resolver, the canary or the graph read."""
    import recon.partial_recon as pr

    def boom(*_a, **_k):
        raise AssertionError("a name was resolved")

    monkeypatch.setattr("recon.helpers.ip_hostnames.dns_resolver", boom)
    monkeypatch.setattr("recon.helpers.ip_hostnames._arm_resolver", boom)
    monkeypatch.setattr("socket.getaddrinfo", boom)
    reads = []
    monkeypatch.setattr(hs, "read_candidates", lambda *a: reads.append(a) or _graph())
    pr._prepare_scope({"tool_id": "Httpx", "domains": ["example.com"]},
                      {"IP_MODE": False, "TARGET_DOMAIN": "example.com", "SUBDOMAIN_LIST": ["."]}, PID)
    for mode in ("ip_only", "record_only"):
        pr._prepare_scope({"tool_id": "Httpx", "domains": [ROOT]}, _settings(mode), PID)
    assert reads == []
    # A scanning mode reads the graph; with nothing recorded or typed it resolves nothing.
    pr._prepare_scope({"tool_id": "Httpx", "domains": [ROOT]}, _settings("record_filter"), PID)
    assert len(reads) == 1 and helpers.run_ip_hostnames() == {}


# ---------------------------------------------------------------------------
# Typed names: refused in the recording modes, pattern-matched then
# re-checked live in record_filter / scan_all
# ---------------------------------------------------------------------------

def _typed(mode, typed, settings_extra=None):
    settings = _settings(mode, **(settings_extra or {}))
    helpers.set_run_ip_targets(settings)
    cfg = {"domain_groups": [], "user_targets": dict(typed)}
    refused = helpers.filter_partial_user_input(cfg, settings)
    return cfg, refused


@pytest.mark.parametrize("mode", ["ip_only", "record_only"])
def test_a_recording_mode_refuses_every_typed_name(mode):
    cfg, refused = _typed(mode, {"subdomains": [APP], "urls": [f"https://{APP}/", f"http://{T1}/"]})
    assert cfg["user_targets"]["subdomains"] == [] and cfg["user_targets"]["urls"] == [f"http://{T1}/"]
    assert all("no typed hostname is scanned" in r for r in refused) and len(refused) == 2


def test_record_filter_takes_a_typed_name_the_filter_admits():
    cfg, refused = _typed("record_filter", {"subdomains": [APP, SHOP, "old.example.com"],
                                            "urls": [f"https://{APP}/x", f"https://{SHOP}/"]},
                          {"IP_HOSTNAME_EXCLUDE": ["old.example.com"]})
    assert cfg["user_targets"]["subdomains"] == [APP]
    assert cfg["user_targets"]["urls"] == [f"https://{APP}/x"]
    assert sorted(refused) == sorted([
        f"subdomain '{SHOP}' (matches no include entry of the hostname filter)",
        "subdomain 'old.example.com' (matches an exclude entry of the hostname filter: old.example.com)",
        f"url 'https://{SHOP}/' (matches no include entry of the hostname filter)",
    ])


def test_scan_all_takes_any_name_but_never_a_hard_blocked_one():
    cfg, refused = _typed("scan_all", {"subdomains": [SHOP, "www.example.gov", "not a name"]})
    assert cfg["user_targets"]["subdomains"] == [SHOP]
    assert any("www.example.gov" in r and "hard guardrail" in r for r in refused)
    assert any("not a name" in r for r in refused)


def test_a_filter_that_cannot_be_read_admits_no_typed_name():
    cfg, refused = _typed("record_filter", {"subdomains": [APP]}, {"IP_HOSTNAME_INCLUDE": None})
    assert cfg["user_targets"]["subdomains"] == []
    assert refused == [f"subdomain '{APP}' (the hostname filter cannot be read)"]


def test_a_typed_name_the_roe_excludes_is_refused_by_the_roe():
    cfg, refused = _typed("record_filter", {"subdomains": [APP]},
                          {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [APP]})
    assert cfg["user_targets"]["subdomains"] == []
    assert refused == [f"subdomain '{APP}' (excluded by the Rules of Engagement)"]


def test_typed_ips_still_attach_only_to_a_label_in_every_mode():
    cfg, refused = _typed("scan_all", {"ips": [T1], "ip_attach_to": APP})
    assert cfg["user_targets"]["ip_attach_to"] is None
    assert refused == [f"ip_attach_to '{APP}' (not a target's own label)"]


def test_a_typed_name_is_re_checked_live_and_dropped_when_it_moved(monkeypatch):
    config = {"domains": [ROOT], "user_inputs": [APP, T1],
              "user_targets": {"subdomains": [APP, API], "urls": [f"https://{API}/", f"http://{T1}/"]}}
    refused, resolver, _, written, cfg = _scope(
        "record_filter", _graph(), {APP: [T1, V6], API: [T1, FOREIGN]}, config=config, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {APP: "example.com"}
    assert cfg["user_inputs"] == [APP, T1]
    assert cfg["user_targets"] == {"subdomains": [APP], "urls": [f"http://{T1}/"]}
    assert refused == {f"hostname {API}": "typed, not scanned (resolves_outside_targets)"}
    assert written == [[APP]]
    assert sorted(resolver.calls) == [API, APP]


def test_scan_all_judges_a_typed_name_on_the_targets_it_resolves_to(monkeypatch):
    attribution = {T1: ("dedicated", []), T2: ("shared_edge", []), V6: ("unknown", ["attribution failed"])}
    config = {"domains": [ROOT], "user_targets": {"subdomains": [APP, API, SHOP]}}
    refused, resolver, _, written, cfg = _scope(
        "scan_all", _graph(attribution=attribution), {APP: [T1], API: [T2], SHOP: [V6]},
        config=config, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {APP: "example.com"}
    assert refused[f"hostname {API}"] == "typed, not scanned (shared_edge_ip)"
    assert refused[f"hostname {SHOP}"] == "typed, not scanned (attribution_unavailable)"
    assert sorted(set(resolver.calls)) == [API, APP, SHOP]
    assert resolver.calls.count(APP) == 1      # the answer it was judged on is the one pinned


def test_a_typed_name_already_scanned_in_the_graph_is_not_written_again(monkeypatch):
    config = {"domains": [ROOT], "user_targets": {"subdomains": [APP]}}
    *_, written, _ = _scope("record_filter", _graph(scanned={APP: [T1]}), {APP: [T1]},
                            config=config, monkeypatch=monkeypatch)
    assert written == []


def test_a_selected_typed_name_is_written_as_a_scanned_name_under_its_org(monkeypatch):
    calls = []

    class _Client:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return True

        def update_graph_from_ip_hostnames(self, recon_data, user_id, project_id):
            calls.append((recon_data, user_id, project_id))
            return {"errors": []}

    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    helpers.set_run_ip_targets(_settings("record_filter"))
    helpers.set_run_ip_hostnames({APP: "example.com"}, {APP: [T1]})
    hs._record_typed({APP}, {APP: "example.com"}, {APP: [T1]}, "u1", PID, ROOT)
    (data, uid, pid), = calls
    assert (uid, pid) == ("u1", PID)
    assert data["metadata"]["ip_mode"] is True and data["metadata"]["root_domain"] == ROOT
    assert data["metadata"]["ip_mode_hosts"] == {APP: "example.com"}
    assert data["ip_hostnames"] == {"candidates": {APP: {
        "reason": "scanned", "org_domain": "example.com", "sources": ["partial_recon_user_input"],
        "resolves_to_now": [T1], "ips_seen": [T1]}}}
    assert "mode" not in data["ip_hostnames"]      # a partial run never stamps the run's mode
    hs._record_typed(set(), {}, {}, "u1", PID, ROOT)
    hs._record_typed({APP}, {APP: "example.com"}, {APP: [T1]}, "", PID, ROOT)
    assert len(calls) == 1


def test_a_typed_name_attaches_to_its_org_domain_never_the_synthetic_root():
    helpers.set_run_ip_targets(_settings("record_filter"))
    helpers.set_run_ip_hostnames({APP: "example.com"}, {APP: [T1]})
    assert helpers.typed_host_domain(APP, [ROOT]) == "example.com"
    assert helpers.typed_host_domain(APP.upper() + ".", [ROOT]) == "example.com"
    assert helpers.typed_host_domain(SHOP, [ROOT]) is None
    assert helpers.typed_host_ok(APP, [ROOT], []) and not helpers.typed_host_ok(SHOP, [ROOT], [])
    helpers.set_run_ip_targets({"IP_MODE": False})
    helpers.set_project_scope([{"scanRoot": "example.com", "orgDomain": "example.com", "mode": "enumerate"}])
    try:
        assert helpers.typed_host_domain(APP, ["example.com"]) == "example.com"
    finally:
        helpers.set_project_scope([])


def test_the_user_subdomain_writer_attaches_to_the_org_in_ip_mode(monkeypatch):
    from recon.partial_recon_modules import user_inputs
    runs = []

    class _Session:
        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def run(self, cypher, **params):
            runs.append((cypher, params))

    class _Client:
        def __init__(self, *_a, **_k):
            self.driver = mock.MagicMock()
            self.driver.session.side_effect = lambda **_k: _Session()

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return True

    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr(user_inputs, "_resolve_hostname", lambda _h: {"ipv4": [T1], "ipv6": []})
    helpers.set_run_ip_targets(_settings("record_filter"))
    helpers.set_run_ip_hostnames({APP: "example.com"}, {APP: [T1]})
    user_inputs._create_user_subdomains_in_graph([ROOT], [APP, SHOP], "u1", PID)
    domains = [p["domain"] for c, p in runs if "HAS_SUBDOMAIN" in c]
    assert domains == ["example.com"]           # SHOP is no target: nothing written for it
    assert all(p.get("domain") != ROOT for _c, p in runs)


# ---------------------------------------------------------------------------
# The name-only tools
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("tool", ["Gau", "ParamSpider", "SubdomainTakeover"])
def test_a_name_only_tool_is_refused_in_the_recording_modes(tool):
    for mode in ("ip_only", "record_only", None):
        settings = dict(BASE, IP_HOSTNAME_MODE=mode)
        reason = helpers.ip_mode_refusal(tool, settings)
        assert reason and reason.startswith(helpers.IP_MODE_REFUSAL), (tool, mode)
        assert "no hostname is a target" in reason
    for mode in ("record_filter", "scan_all"):
        assert helpers.ip_mode_refusal(tool, dict(BASE, IP_HOSTNAME_MODE=mode)) is None
    assert helpers.ip_mode_refusal(tool, {"IP_MODE": False}) is None


def test_dispatch_reads_the_runs_hostname_mode(monkeypatch):
    import recon.partial_recon as pr
    called = []
    monkeypatch.setattr(pr, "run_gau", lambda cfg: called.append("Gau"))
    statuses = pr._dispatch("Gau", {"domains": [ROOT], "ip_mode": True, "ip_hostname_mode": "record_only"})
    assert called == [] and pr.run_exit_code(statuses) == 1
    pr._dispatch("Gau", {"domains": [ROOT], "ip_mode": True, "ip_hostname_mode": "record_filter"})
    assert called == ["Gau"]


def test_main_refuses_a_name_only_tool_with_a_run_report(monkeypatch, capsys):
    import recon.partial_recon as pr
    monkeypatch.setattr(pr, "load_config", lambda: {"tool_id": "ParamSpider", "domains": [ROOT]})
    monkeypatch.setattr(pr, "get_settings", lambda: _settings("record_only"))
    monkeypatch.setattr("recon.graph_db_preflight.require_graph_db", lambda *_a: None)
    monkeypatch.setattr(pr, "_prepare_scope", lambda *_a: pytest.fail("the scope pass ran"))
    with pytest.raises(SystemExit) as exit_info:
        pr.main()
    assert exit_info.value.code == 1
    out = capsys.readouterr().out
    assert "Run report: ParamSpider" in out and "no hostname is a target" in out


# ---------------------------------------------------------------------------
# The four predicates: builders, URL scope, _is_host_in_scope, typed input
# ---------------------------------------------------------------------------

class _Result(list):
    def single(self):
        return self[0] if self else None


ROWS = {ROOT: [(LABEL, T1), (OLD_PTR, T1)],
        "example.com": [(APP, T1), ("gone.example.com", T2)]}


class _Session:
    def __init__(self, log, baseurls=()):
        self.log, self.baseurls = log, baseurls

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        self.log.append((cypher, params))
        out = _Result()
        domains = [str(d).lower() for d in params.get("domains") or []]
        if "HAS_SUBDOMAIN" in cypher and "RESOLVES_TO" in cypher:
            for root in domains:
                for sub, ip in ROWS.get(root, []):
                    out.append({"root": root, "subdomain": sub, "address": ip, "ip": ip, "version": None,
                                "ports": [{"number": 443, "protocol": "tcp", "passive_only": None}],
                                "is_cdn": None, "cdn_name": None, "asn": None})
        elif "collect(DISTINCT s.name)" in cypher:
            out.append({"subdomains": sorted({s for root in domains for s, _ in ROWS.get(root, [])})})
        elif "MATCH (b:BaseURL" in cypher and "AS status_code" in cypher:
            for url, host in self.baseurls:
                out.append({"url": url, "host": host, "status_code": 200, "content_type": "text/html"})
        return out


class _Client:
    log: list = []
    baseurls: tuple = ()

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
        driver.session.side_effect = lambda **_k: _Session(_Client.log, _Client.baseurls)
        return driver


@pytest.fixture
def graph(monkeypatch):
    _Client.log, _Client.baseurls = [], ()
    monkeypatch.setattr("graph_db.Neo4jClient", _Client)
    monkeypatch.setattr("graph_db.neo4j_client.Neo4jClient", _Client)
    return _Client


def _ip_run(mode, names=None):
    helpers.set_run_ip_targets(_settings(mode))
    helpers.set_run_ip_hostnames(names or {}, {n: [T1] for n in names or {}})


@pytest.mark.parametrize("mode", ["ip_only", "record_only"])
def test_the_builders_keep_only_the_labels_in_a_recording_mode(graph, mode):
    _ip_run(mode)
    data = gb._build_port_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["port_scan"]["by_host"]) == [T1]
    assert data["port_scan"]["by_ip"][T1]["hostnames"] == []
    assert "ip_mode_hosts" not in data["metadata"]
    # The org Domains are never read: S is empty.
    assert all(p.get("domains") in (None, [ROOT]) for _c, p in graph.log)


def test_the_builders_keep_s_under_its_org_domain(graph):
    _ip_run("record_filter", {APP: "example.com"})
    data = gb._build_port_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["port_scan"]["by_host"]) == [T1, APP]
    assert data["port_scan"]["by_ip"][T1]["hostnames"] == [APP]
    assert data["metadata"]["ip_mode_hosts"] == {APP: "example.com"}
    assert any(p.get("domains") == [ROOT, "example.com"] for _c, p in graph.log)
    flat = gb._build_http_probe_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(flat["subdomains"]) == [LABEL, APP]
    data = gb._build_recon_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["dns"]["subdomains"]) == [LABEL, APP]


def test_the_writers_scope_list_keeps_labels_and_s_only(graph):
    _ip_run("record_filter", {APP: "example.com"})
    session = _Session(graph.log)
    assert sorted(gb.graph_scope_subdomains(session, "u1", PID, [ROOT], [])) == [LABEL, APP]


def test_the_url_scope_keeps_t_and_s_and_real_org_domain_baseurls(graph):
    _ip_run("record_filter", {APP: "example.com"})
    graph.baseurls = ((f"https://{APP}", APP), ("https://gone.example.com", "gone.example.com"),
                      (f"http://{T1}", T1), (f"http://{FOREIGN}", FOREIGN), (f"http://{LABEL}", LABEL),
                      (f"http://{OLD_PTR}", OLD_PTR))
    data = gb._build_http_probe_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert sorted(data["http_probe"]["by_url"]) == sorted([f"https://{APP}", f"http://{T1}"])
    keep = gb.graph_url_scope(_Session(graph.log), "u1", PID, [ROOT], [])
    assert keep(APP) and keep(APP.upper()) and keep(T1) and keep("")
    assert not keep("gone.example.com") and not keep(LABEL) and not keep(FOREIGN)


def test_the_url_scope_keeps_no_name_in_a_recording_mode(graph):
    _ip_run("record_only")
    keep = gb.graph_url_scope(_Session(graph.log), "u1", PID, [ROOT], [])
    assert keep(T1) and not keep(APP)


def test_the_archive_hosts_are_s(graph):
    _ip_run("record_filter", {APP: "example.com", API: "example.com"})
    assert gb.graph_target_hosts("u1", PID, [ROOT], []) == [API, APP]
    assert gb.graph_target_hosts("u1", PID, [ROOT], [], include_graph=False) == []
    helpers.set_run_roe({"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [API]})
    assert gb.graph_target_hosts("u1", PID, [ROOT], []) == [APP]


def test_is_host_in_scope_is_t_or_s_and_fails_closed():
    _ip_run("record_filter", {APP: "example.com"})
    settings = dict(BASE, TARGET_IPS=["203.0.113.0/30", V6], ROE_ENABLED=True,
                    ROE_EXCLUDED_HOSTS=["203.0.113.2"])
    f = helpers._is_host_in_scope
    assert f(T1, settings) and f(f"[{V6}]:8443", settings) and f("2001:DB8:0::1", settings)
    assert f(APP, settings) and f(f"{APP}:443", settings)
    assert not f("203.0.113.2", settings)             # RoE-excluded target
    assert not f("203.0.113.3", settings)             # the /30's broadcast address is no target
    assert not f(SHOP, settings) and not f(FOREIGN, settings)
    empty = dict(BASE, TARGET_IPS=[])
    for host in ("10.0.0.1", "127.0.0.1", "localhost", APP):
        assert not f(host, empty) or host == APP, host


# ---------------------------------------------------------------------------
# VHost/SNI: the recorded names by mode (P3 carry-forward)
# ---------------------------------------------------------------------------

def test_the_vhost_block_reads_recorded_names_and_s(monkeypatch):
    rows = {"recorded": {"seen.example.net": {"ips": [T1], "reason": "record_only"},
                         "blocked.example.gov": {"ips": [T1], "reason": "hard_blocked"}},
            "scanned": {APP: [T1]}, "excluded": set(), "attribution": None}
    monkeypatch.setattr(hs, "read_candidates", lambda *_a: rows)
    helpers.set_run_ip_targets(_settings("record_filter"))
    helpers.set_run_ip_hostnames({APP: "example.com"}, {APP: [T1, V6]})
    block = hs.vhost_hostnames_block("u1", PID, _settings("record_filter"))
    assert block["mode"] == "record_filter"
    assert block["candidates"]["seen.example.net"] == {"reason": "record_only", "ips_seen": [T1]}
    assert block["candidates"]["blocked.example.gov"]["reason"] == "hard_blocked"
    assert block["candidates"][APP] == {"reason": "scanned", "ips_seen": [], "resolves_to_now": [T1, V6]}
    from recon.helpers.ip_hostnames import may_send
    assert not may_send(block["candidates"]["blocked.example.gov"])
    assert hs.vhost_hostnames_block("u1", PID, _settings("ip_only")) == {"mode": "ip_only", "candidates": {}}
    monkeypatch.setattr(hs, "read_candidates", lambda *_a: None)
    assert hs.vhost_hostnames_block("u1", PID, _settings("record_only")) == {"mode": "record_only",
                                                                            "candidates": {}}


def test_the_ownership_load_carries_the_reasons(monkeypatch):
    class _OwnSession(_Session):
        def run(self, cypher, **params):
            return _Result([{"ip": T1, "ownership": "unknown", "reasons": ["attribution failed"]}])

    class _OwnClient(_Client):
        @property
        def driver(self):
            driver = mock.MagicMock()
            driver.session.side_effect = lambda **_k: _OwnSession([])
            return driver

    monkeypatch.setattr("graph_db.Neo4jClient", _OwnClient)
    data = {"port_scan": {"by_ip": {T1: {}}}}
    gb.attach_graph_ownership(data, "u1", PID)
    assert data["ip_attribution"]["by_ip"][T1] == {"ownership": "unknown",
                                                   "ownership_reasons": ["attribution failed"]}


# ---------------------------------------------------------------------------
# httpx keeps the results of S
# ---------------------------------------------------------------------------

def test_httpx_keeps_the_results_of_s_and_the_targets():
    _ip_run("record_filter", {APP: "example.com"})
    data = helpers.ip_mode_recon({"domain": ROOT, "metadata": {}})
    helpers.keep_selected_names(data)
    meta = data["metadata"]
    assert meta["filtered_mode"] is True
    assert set(meta["subdomain_filter"]) >= {APP, T1, T2, V6}
    _ip_run("record_only")
    data = helpers.ip_mode_recon({"domain": ROOT, "metadata": {}})
    helpers.keep_selected_names(data)
    assert "filtered_mode" not in data["metadata"]


def test_a_partial_httpx_result_reaches_the_label_subdomain_through_the_writer(graph):
    """L-18 for partial runs: httpx keys a target's row by its address, the
    graph holds the label, and the HTTP writer translates through
    metadata.ip_to_hostname, which every partial IP-mode dict now carries. A
    name in S is keyed by its own name and keeps matching itself. The real
    writer runs; only its Neo4j session is a fake."""
    from graph_db.mixins.recon.http_mixin import HttpMixin
    _ip_run("record_filter", {APP: "example.com"})
    data = gb._build_port_scan_data_from_graph([ROOT], "u1", PID, domain_groups=[])
    assert data["metadata"]["ip_to_hostname"][T1] == LABEL
    assert data["metadata"]["ip_to_hostname"][APP] == APP

    def host(name, codes):
        url = f"https://{name}/"
        return {"hostname": name, "urls": [url], "live_urls": [url], "technologies": [], "servers": [],
                "status_codes": codes}

    data["subdomains"] = [LABEL, APP]
    data["http_probe"] = {"scan_metadata": {}, "by_url": {},
                          "by_host": {T1: host(T1, [200, 404]), APP: host(APP, [301])}}

    class _WResult:
        def single(self):
            return {"linked": 0, "count": 0, "c": 0}

        def __iter__(self):
            return iter([])

    class _WSession:
        def __init__(self, queries):
            self.queries = queries

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def run(self, query, **kwargs):
            self.queries.append((query, kwargs))
            return _WResult()

    class _Writer(HttpMixin):
        def __init__(self):
            self.queries = []
            self.driver = mock.MagicMock()
            self.driver.session.side_effect = lambda *_a, **_k: _WSession(self.queries)

    writer = _Writer()
    writer.update_graph_from_http_probe(data, "u1", PID)
    statuses = {kw["hostname"]: kw["status"] for q, kw in writer.queries if "SET s.status = $status" in q}
    assert statuses == {LABEL: "200", APP: "301"}


# ---------------------------------------------------------------------------
# A typed name keeps the source the hostname writer gave it
# ---------------------------------------------------------------------------

class _SourceStore:
    """The Subdomain `source` property, written by the three statement shapes
    the partial modules use: ON CREATE (first writer only), coalesce (keep an
    existing one), plain assignment (overwrite). Every other statement only
    records itself and returns an empty result."""

    def __init__(self, sources):
        self.sources, self.statements = dict(sources), []

    def run(self, query, **params):
        self.statements.append(query)
        if "MERGE (s:Subdomain" in query and "s.source" in query:
            name = params.get("name") or params.get("sub")
            if "coalesce(s.source, 'partial_recon_user_input')" in query or "ON CREATE SET s.source" in query:
                self.sources.setdefault(name, "partial_recon_user_input")
            else:
                self.sources[name] = "partial_recon_user_input"
        result = mock.MagicMock()
        result.__iter__ = lambda _self: iter([])
        result.single.return_value = None
        return result


def _store_client(store):
    class _Session:
        def __enter__(self):
            return store

        def __exit__(self, *_a):
            return False

    class _Client:
        def __init__(self, *_a, **_k):
            self.driver = mock.MagicMock()
            self.driver.session.side_effect = lambda *_a, **_k: _Session()

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return True

        def update_graph_from_http_probe(self, *_a, **_k):
            return {}

        def update_graph_from_port_scan(self, *_a, **_k):
            return {}

    return _Client


@pytest.mark.parametrize("tool", ["Httpx", "Naabu"])
def test_a_typed_names_selection_source_survives_the_modules_own_write(tool, monkeypatch):
    """The typed name was written as a scanned name (source
    ip_hostname_selection) before the tool ran; the module's own Subdomain
    write must not turn it into partial_recon_user_input, or the name drops
    out of the next run's S, the narrowing marker and the agent's list."""
    store = _SourceStore({APP: "ip_hostname_selection"})
    monkeypatch.setattr("graph_db.Neo4jClient", _store_client(store))
    monkeypatch.setattr("recon.main_recon_modules.http_probe.run_http_probe",
                        lambda recon_data, **_k: recon_data)
    monkeypatch.setattr("recon.main_recon_modules.port_scan.run_port_scan",
                        lambda recon_data, **_k: recon_data)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    settings = _settings("record_filter")
    helpers.set_run_ip_targets(settings)
    helpers.set_run_ip_hostnames({APP: "example.com"}, {APP: [T1]})
    config = {"domains": [ROOT], "domain_groups": [], "include_graph_targets": False,
              "user_targets": {"subdomains": [APP]}, "_settings": settings}
    from recon.partial_recon_modules.http_probing import run_httpx
    from recon.partial_recon_modules.port_scanning import run_naabu
    runner = run_httpx if tool == "Httpx" else run_naabu
    runner(config)
    assert any("MERGE (s:Subdomain" in q for q in store.statements), "the typed-name write never ran"
    assert store.sources[APP] == "ip_hostname_selection"
    # A name nobody wrote before still gets the module's own source.
    store = _SourceStore({})
    monkeypatch.setattr("graph_db.Neo4jClient", _store_client(store))
    runner(dict(config, user_targets={"subdomains": [APP]}))
    assert store.sources[APP] == "partial_recon_user_input"


# ---------------------------------------------------------------------------
# The graph read itself
# ---------------------------------------------------------------------------

def test_read_candidates_splits_scanned_recorded_and_excluded(monkeypatch):
    rows = {
        "SCANNED": [{"name": "App.Example.com.", "reason": "scanned", "ips": [T1, None]},
                    {"name": "old.example.com", "reason": "out_of_policy", "ips": [T1]},
                    {"name": None, "reason": "scanned", "ips": []}],
        "RECORDED": [{"name": "old.example.com", "reason": "filter_no_match", "ips": [T1]},
                     {"name": "seen.example.net", "reason": "record_only", "ips": [T2, T2]},
                     # Also a scanned Subdomain: the scanned row is the candidate.
                     {"name": APP, "reason": "filter_no_match", "ips": [T1]},
                     {"name": "*.wild.example.com", "reason": "invalid_name", "ips": [T1]}],
        "OWNERSHIP": [{"ip": T1, "ownership": "dedicated", "reasons": None}],
    }

    class _ReadSession(_Session):
        def run(self, cypher, **params):
            assert params["uid"] == "u1" and params["pid"] == PID
            key = ("SCANNED" if "ip_hostname_selection" in cypher
                   else "RECORDED" if "SEEN_ON" in cypher else "OWNERSHIP")
            return _Result(rows[key])

    class _ReadClient(_Client):
        reachable = True

        def verify_connection(self):
            return _ReadClient.reachable

        @property
        def driver(self):
            driver = mock.MagicMock()
            driver.session.side_effect = lambda **_k: _ReadSession([])
            return driver

    monkeypatch.setattr("graph_db.Neo4jClient", _ReadClient)
    got = hs.read_candidates("u1", PID)
    assert got["scanned"] == {APP: [T1]}
    assert got["excluded"] == {"old.example.com"}
    assert got["recorded"] == {"seen.example.net": {"ips": [T2], "reason": "record_only"}}
    assert got["attribution"] == {T1: ("dedicated", [])}
    _ReadClient.reachable = False
    assert hs.read_candidates("u1", PID) is None
    monkeypatch.setattr("graph_db.Neo4jClient", mock.MagicMock(side_effect=RuntimeError("down")))
    assert hs.read_candidates("u1", PID) is None


# ---------------------------------------------------------------------------
# The remaining paths of the new code
# ---------------------------------------------------------------------------

def test_the_default_resolver_is_the_full_runs(monkeypatch):
    asked = []
    monkeypatch.setattr("recon.helpers.ip_hostnames.dns_resolver",
                        lambda settings: (lambda name: asked.append(name) or [T1]))
    monkeypatch.setattr(hs, "read_candidates", lambda *_a: _graph(scanned={APP: [T1]}))
    helpers.set_run_ip_targets(_settings("record_filter"))
    hs.run_hostname_scope({"domains": [ROOT]}, _settings("record_filter"), "u1", PID)
    assert asked == [APP] and helpers.run_ip_hostnames() == {APP: "example.com"}


def test_a_typed_name_with_no_answer_is_refused_in_scan_all(monkeypatch):
    attribution = {T1: ("dedicated", []), T2: ("dedicated", []), V6: ("dedicated", [])}
    config = {"domains": [ROOT], "user_targets": {"subdomains": [APP]}}
    refused, resolver, *_ = _scope("scan_all", _graph(attribution=attribution), {APP: OSError("timeout")},
                                   config=config, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostnames() == {}
    assert refused[f"hostname {APP}"] in ("typed, not scanned (attribution_unavailable)",
                                          "typed, not scanned (resolver_unavailable)")
    # DNS off: nothing is looked up, the name is refused as such.
    refused, resolver, *_ = _scope("scan_all", _graph(attribution=attribution), {APP: [T1]},
                                   config={"domains": [ROOT], "user_targets": {"subdomains": [APP]}},
                                   monkeypatch=monkeypatch, DNS_ENABLED=False)
    assert resolver.calls == []
    assert refused[f"hostname {APP}"] == "typed, not scanned (attribution_unavailable)"


def test_a_scanned_name_is_never_resolved_twice_and_the_answer_is_pinned(monkeypatch):
    _scope("record_filter", _graph(scanned={APP: [T1]}), {APP: [V6, T1]}, monkeypatch=monkeypatch)
    assert helpers.run_ip_hostname_answer(APP) == sorted([V6, T1])
    assert helpers._resolve_hostname(APP) == {"ipv4": [T1], "ipv6": [V6]}
    assert helpers.run_ip_hostname_answer(SHOP) == []


def test_recording_a_typed_name_never_fails_the_run(monkeypatch, capsys):
    helpers.set_run_ip_targets(_settings("record_filter"))
    helpers.set_run_ip_hostnames({APP: "example.com"}, {APP: [T1]})

    class _Down:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return False

    monkeypatch.setattr("graph_db.Neo4jClient", _Down)
    hs._record_typed({APP}, {APP: "example.com"}, {APP: [T1]}, "u1", PID, ROOT)
    assert "not written" in capsys.readouterr().out

    class _Errors(_Down):
        def verify_connection(self):
            return True

        def update_graph_from_ip_hostnames(self, *_a):
            return {"errors": ["boom"]}

    monkeypatch.setattr("graph_db.Neo4jClient", _Errors)
    hs._record_typed({APP}, {APP: "example.com"}, {APP: [T1]}, "u1", PID, ROOT)
    assert "1 write(s) failed" in capsys.readouterr().out
    monkeypatch.setattr("graph_db.Neo4jClient", mock.MagicMock(side_effect=RuntimeError("down")))
    hs._record_typed({APP}, {APP: "example.com"}, {APP: [T1]}, "u1", PID, ROOT)
    assert "Could not write the typed hostnames (RuntimeError)" in capsys.readouterr().out


def test_the_typed_name_rule_refuses_a_filter_entry_it_cannot_parse():
    settings = _settings("record_filter", IP_HOSTNAME_EXCLUDE=["*.*"])
    assert helpers.typed_name_refusal(APP, settings) == "the hostname filter cannot be read"
    assert helpers.typed_name_refusal(APP, _settings("record_filter", IP_HOSTNAME_EXCLUDE="x")) \
        == "the hostname filter cannot be read"


def test_a_typed_address_or_cidr_as_a_hostname_is_judged_as_an_address():
    cfg, refused = _typed("scan_all", {"subdomains": [T1, "203.0.113.0/30", "198.51.100.7"]})
    assert cfg["user_targets"]["subdomains"] == [T1]
    assert len(refused) == 2 and not any("hostname" in r for r in refused)


def test_the_typed_inputs_are_dropped_only_where_they_are_lists():
    config = {"user_inputs": "not-a-list", "user_targets": {"subdomains": "x", "urls": [7, f"https://{APP}/"]}}
    hs._drop_typed(config, {APP})
    assert config == {"user_inputs": "not-a-list", "user_targets": {"subdomains": "x", "urls": [7]}}
    config = {"user_targets": None}
    hs._drop_typed(config, {APP})
    assert config == {"user_targets": None}
    assert hs._typed_names({"user_inputs": [None, 7, "", f"[{V6}]"], "user_targets": {"urls": [None]}}) == set()


def test_the_vhost_partial_reads_its_candidates_from_the_graph_in_ip_mode(monkeypatch):
    from recon.partial_recon_modules import vulnerability_scanning as vs
    seen = {}
    monkeypatch.setattr(vs, "_build_vuln_scan_data_from_graph", lambda *_a, **_k: helpers.ip_mode_recon({
        "domain": ROOT, "domains": [ROOT], "subdomains": [],
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False}, "subdomains": {}},
        "http_probe": {"by_url": {}}, "port_scan": {"by_host": {T1: {"ip": T1, "ports": [443]}}}}))
    monkeypatch.setattr(vs, "attach_graph_ownership", lambda *_a: None)
    monkeypatch.setattr(hs, "vhost_hostnames_block",
                        lambda uid, pid, settings: {"mode": settings["IP_HOSTNAME_MODE"], "candidates": {}})
    monkeypatch.setattr("recon.main_recon_modules.vhost_sni_enum.run_vhost_sni_enrichment",
                        lambda recon_data, settings=None: seen.setdefault("block", recon_data.get("ip_hostnames")))

    class _Down:
        def __init__(self, *_a, **_k):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *_a):
            return False

        def verify_connection(self):
            return False

    monkeypatch.setattr("graph_db.Neo4jClient", _Down)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    helpers.set_run_ip_targets(_settings("record_only"))
    vs.run_vhost_sni_partial({"domains": [ROOT], "_settings": _settings("record_only")})
    assert seen["block"] == {"mode": "record_only", "candidates": {}}
