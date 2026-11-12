"""Partial Subdomain Takeover honours each root's Include Root (L-22).

A partial run hands the takeover scan a `domains` list (every partial builder
sets one), and `_collect_subdomains` used to add every root in it and skip the
group scope for a list. A root whose group leaves Include Root off was still
given to Subjack and BadDNS, though the partial builders, the typed-input
filter and the graph writers (scope.classify_host: SKIPPED) all treat it as no
target. The rule is now per root: its scope group's include_root (the groups
partial_recon._prepare_scope records through set_project_scope, or the dict's
own scope_groups), else the dict's include_root_domain (a legacy builder
without groups), else on as before.

The real collector and the real partial entry point run; only Neo4j, DNS and
the Subjack / BadDNS containers are replaced. IP mode keeps its own rule
(test_takeover_ip_mode_selected_names.py). Documentation ranges and reserved
names only.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.helpers.batch_groups import settings_scope_groups  # noqa: E402
from recon.main_recon_modules import subdomain_takeover as st  # noqa: E402
from recon.partial_recon_modules import vulnerability_scanning  # noqa: E402
from recon.partial_recon_modules.helpers import partial_domain_groups, set_project_scope  # noqa: E402

COM, ORG = "example.com", "example.org"
WWW, API = f"www.{COM}", f"api.{ORG}"


def _group(root, include_root, mode="enumerate", exact=()):
    return {"scanRoot": root, "orgDomain": root, "mode": mode,
            "includeRoot": include_root, "exactHosts": list(exact)}


def _settings(*groups, **extra):
    return {"SCOPE_GROUPS": list(groups), "DOMAIN_BATCH_MODE": len(groups) > 1, **extra}


@pytest.fixture(autouse=True)
def _run_scope():
    """The scope partial_recon._prepare_scope writes for the modules; cleared
    after each test so no group leaks into the next."""
    def apply(settings):
        set_project_scope(settings_scope_groups(settings))
    yield apply
    set_project_scope([])


def _partial(roots, hosts, metadata=None):
    """The dict _build_vuln_scan_data_from_graph returns for `roots`."""
    run = {
        "domain": roots[0], "domains": list(roots), "subdomains": list(hosts),
        "dns": {"domain": {"ips": {"ipv4": [], "ipv6": []}, "has_records": False},
                "subdomains": {h: {"ips": {"ipv4": ["192.0.2.10"], "ipv6": []}, "has_records": True}
                               for h in hosts}},
        "http_probe": {"by_url": {}},
    }
    if metadata is not None:
        run["metadata"] = metadata
    return run


class TestCollectSubdomains:
    def test_a_root_with_include_root_off_is_not_checked(self, _run_scope):
        _run_scope(_settings(_group(COM, False)))
        run = _partial([COM], [WWW], {"include_root_domain": False})
        assert st._collect_subdomains(run, {}) == [WWW]

    def test_each_root_follows_its_own_group(self, _run_scope):
        _run_scope(_settings(_group(COM, False), _group(ORG, True)))
        run = _partial([COM, ORG], [WWW, API], {"include_root_domain": False})
        assert sorted(st._collect_subdomains(run, {})) == sorted([WWW, ORG, API])

    def test_the_first_root_on_and_another_off(self, _run_scope):
        _run_scope(_settings(_group(COM, True), _group(ORG, False)))
        run = _partial([COM, ORG], [WWW, API], {"include_root_domain": True})
        assert sorted(st._collect_subdomains(run, {})) == sorted([COM, WWW, API])

    def test_the_group_decides_for_a_dict_without_metadata(self, _run_scope):
        """The typed-only run (no graph targets) builds its dict with no
        include_root_domain at all."""
        _run_scope(_settings(_group(COM, False)))
        assert st._collect_subdomains(_partial([COM], [WWW]), {}) == [WWW]

    def test_the_dicts_own_scope_groups_are_read_too(self):
        run = _partial([COM], [WWW])
        run["scope_groups"] = [{"scan_root": COM, "org_domain": COM, "mode": "enumerate",
                                "include_root": False, "exact_hosts": []}]
        assert st._collect_subdomains(run, {}) == [WWW]

    def test_a_root_the_dns_block_lists_is_still_dropped(self, _run_scope):
        _run_scope(_settings(_group(COM, False), _group(ORG, False)))
        run = _partial([COM, ORG], [WWW, ORG])
        assert st._collect_subdomains(run, {}) == [WWW]

    def test_a_legacy_dict_without_groups_follows_its_flag(self):
        assert st._collect_subdomains(_partial([COM, ORG], [WWW], {"include_root_domain": False}), {}) == [WWW]
        assert sorted(st._collect_subdomains(_partial([COM, ORG], [WWW]), {})) == sorted([COM, ORG, WWW])

    def test_the_full_run_group_form_is_unchanged(self):
        for include_root, expected in ((True, [COM, WWW]), (False, [WWW])):
            run = {"domain": COM, "dns": {"subdomains": {WWW: {}}},
                   "metadata": {"scope_mode": "enumerate", "include_root_domain": include_root,
                                "root_domain": COM},
                   "scope_groups": [{"scan_root": COM, "org_domain": COM, "mode": "enumerate",
                                     "include_root": include_root, "exact_hosts": []}]}
            assert sorted(st._collect_subdomains(run, {})) == expected


# --- The partial entry point, end to end -----------------------------------

class _Result:
    def __iter__(self):
        return iter([])

    def single(self):
        return None

    def data(self):
        return []


class _Session:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        return _Result()


class _Driver:
    def session(self):
        return _Session()


class _EmptyGraph:
    """A reachable Neo4j with nothing in it; the takeover writer is recorded."""
    writes = []

    def __init__(self, *a, **kw):
        self.driver = _Driver()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def verify_connection(self):
        return True

    def update_graph_from_subdomain_takeover(self, recon_data, user_id, project_id):
        _EmptyGraph.writes.append(recon_data.get("subdomain_takeover"))
        return {}


@pytest.fixture
def tools(monkeypatch, tmp_path):
    import graph_db
    monkeypatch.setattr(graph_db, "Neo4jClient", _EmptyGraph)
    monkeypatch.setattr(vulnerability_scanning, "_resolve_hostname",
                        lambda host: {"ipv4": ["192.0.2.10"], "ipv6": []})
    handed = {}

    def capture(name):
        def run(subdomains, work_dir, settings):
            handed[name] = list(subdomains)
            return []
        return run

    monkeypatch.setattr(st, "_run_subjack", capture("subjack"))
    monkeypatch.setattr(st, "_run_baddns", capture("baddns"))
    _EmptyGraph.writes = []
    return handed


def _run_partial(settings, roots, typed):
    config = {"domains": list(roots), "domain": roots[0], "_settings": settings,
              "domain_groups": partial_domain_groups(settings, roots),
              "user_targets": {"subdomains": list(typed)}}
    vulnerability_scanning.run_subdomain_takeover_partial(config)


SCAN = {"SUBJACK_ENABLED": True, "BADDNS_ENABLED": True, "NUCLEI_TAKEOVERS_ENABLED": False,
        "TAKEOVER_AI_CLASSIFIER": False}


class TestPartialEntryPoint:
    def test_subjack_and_baddns_never_get_a_root_left_out(self, tools, _run_scope):
        settings = _settings(_group(COM, False), **SCAN)
        _run_scope(settings)
        _run_partial(settings, [COM], [WWW])
        assert tools == {"subjack": [WWW], "baddns": [WWW]}
        assert _EmptyGraph.writes, "the takeover writer was not reached"

    def test_an_included_root_is_still_checked(self, tools, _run_scope):
        settings = _settings(_group(COM, False), _group(ORG, True), **SCAN)
        _run_scope(settings)
        _run_partial(settings, [COM, ORG], [WWW, API])
        assert tools["subjack"] == sorted([ORG, API, WWW])
        assert tools["baddns"] == tools["subjack"]
