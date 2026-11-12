"""A link a crawler or an archive saw never mints a Subdomain (D2, R-2).

Every crawler (Katana, Hakrawler, GAU, jsluice, the ZAP spider, FFuf, Arjun),
httpx's and urlscan's redirects and JS Recon record a host outside the run's
target list as an "external domain". The pipeline aggregates them at its end
(recon/helpers/external_domains.py) and update_graph_from_external_domains
MERGEd a Subdomain, with BELONGS_TO and HAS_SUBDOMAIN, for every one under a
project root, whatever the run had decided about it. A name the RoE excluded,
one an EXACT group never listed, one a wildcard zone answered: each became a
Subdomain with the crawler as its source, and partial Naabu, httpx and Nuclei
read every Subdomain back as a target. The final E2E found shop.nwlab.test,
RoE-excluded and never requested, written that way by Hakrawler.

The writer now only links a name to a Subdomain the tenant's graph already
holds, as the Uncover (d1d4aa63) and tlsx (00b21d3f) writers link theirs: the
names a run admits are written by the steps that admit them. IP mode is
unchanged: its in-scope names are the ones the hostname rule selected.

The real Hakrawler output filter, aggregator and writer run; Docker and Neo4j
are the fakes (an empty graph). Only reserved names and RFC 5737 addresses.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock
from unittest.mock import MagicMock

import pytest

_RECON = Path(__file__).resolve().parent.parent
_REPO = _RECON.parent
for _p in (str(_REPO), str(_RECON)):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from recon.helpers import circuit_breaker  # noqa: E402
from recon.helpers.external_domains import _aggregate_external_domains  # noqa: E402
from recon.helpers.resource_enum.hakrawler_helpers import run_hakrawler_crawler  # noqa: E402

ROOT = "example.com"
SIBLING_ROOT = "example.net"
KEPT = "www.example.com"
EXCLUDED = "shop.example.com"
UNLISTED = "v1.api.example.com"
SIBLING_HOST = "api.example.net"
FOREIGN = "cdn.example.org"
ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": ["192.0.2.62/32", EXCLUDED]}
UID, PID = "u1", "proj-crawl-link"

_MINT = re.compile(r"\b(MERGE|CREATE)\s*\(\s*\w*\s*:\s*Subdomain\b")


@pytest.fixture(autouse=True)
def _fresh_breakers():
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


class _Session:
    """Records every statement and answers no rows: an empty graph."""

    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def run(self, cypher, **params):
        self.calls.append((cypher, params))
        result = MagicMock()
        result.single.return_value = {"is_new": True}
        result.__iter__ = lambda _s: iter([])
        return result


def _write(recon: dict):
    session = _Session()
    writer = OsintMixin()
    writer.driver = MagicMock()
    writer.driver.session.return_value = session
    writer.update_graph_from_external_domains(recon, UID, PID)
    return session


def _minted(session) -> set:
    """Every name a statement may create a Subdomain node for."""
    return {params.get("name") for cypher, params in session.calls if _MINT.search(cypher)}


def _lookups(session) -> dict:
    """{name: org} for every link of a name to its org Domain."""
    return {params["name"]: params["domain"] for cypher, params in session.calls
            if "HAS_SUBDOMAIN" in cypher and "name" in params}


def _externals(session) -> list:
    return [params["ed_domain"] for cypher, params in session.calls
            if "MERGE (ed:ExternalDomain" in cypher]


def _hakrawler_externals(lines: list, allowed: set) -> list:
    """What the real Hakrawler wrapper records for the hosts it filtered out."""
    def fake_popen(cmd, **_kwargs):
        proc = MagicMock()
        proc.stdout.readline.side_effect = [f"{line}\n" for line in lines] + [""]
        proc.poll.return_value = 0
        proc.wait.return_value = 0
        proc.returncode = 0
        return proc

    with mock.patch("subprocess.Popen", side_effect=fake_popen):
        _urls, meta = run_hakrawler_crawler(
            target_urls=[f"https://{KEPT}/"], docker_image="jauderho/hakrawler:latest",
            depth=2, threads=1, timeout=5, max_urls=100, include_subs=False,
            insecure=True, allowed_hosts={KEPT}, custom_headers=[], exclude_patterns=[],
            parallelism=1, settings=dict(ROE), recon_data={"domain": ROOT},
        )
    return meta["external_domains"]


def _group(**extra) -> dict:
    """One ENUMERATE group's recon dict at the end of the domain pipeline."""
    recon = {"domain": ROOT, "subdomains": [KEPT],
             "metadata": {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": "enumerate",
                          "include_root_domain": False}}
    recon.update(extra)
    return recon


def _aggregated(recon: dict) -> dict:
    """main.py's last step: aggregate, then the writer reads the aggregate."""
    recon["external_domains_aggregated"] = _aggregate_external_domains(recon)
    return recon


# --------------------------------------------------------------------------- #
# The E2E case: Hakrawler's link to an RoE-excluded name
# --------------------------------------------------------------------------- #
def test_a_hakrawler_link_to_an_roe_excluded_name_mints_no_subdomain():
    externals = _hakrawler_externals(
        [f"https://{KEPT}/about", f"https://{EXCLUDED}/", f"https://{FOREIGN}/lib.js"], {KEPT})
    assert {"domain": EXCLUDED, "source": "hakrawler", "url": f"https://{EXCLUDED}/"} in externals

    session = _write(_aggregated(_group(resource_enum={"external_domains": externals})))

    assert EXCLUDED not in _minted(session)
    assert _minted(session) == set()
    assert _externals(session) == [FOREIGN]


def test_an_in_scope_link_is_a_tenant_scoped_lookup_only():
    session = _write(_aggregated(_group(resource_enum={"external_domains": [
        {"domain": EXCLUDED, "source": "hakrawler", "url": f"https://{EXCLUDED}/"}]})))

    assert _lookups(session) == {EXCLUDED: ROOT}
    for cypher, params in session.calls:
        if "HAS_SUBDOMAIN" in cypher:
            assert "MATCH (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})" in cypher
            assert "MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})" in cypher
            assert (params["uid"], params["pid"]) == (UID, PID)


# --------------------------------------------------------------------------- #
# Every source that feeds the same aggregate
# --------------------------------------------------------------------------- #
_ENTRY = {"domain": UNLISTED, "url": f"https://{UNLISTED}/"}

SOURCES = {
    "gau": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "gau"}]}},
    "katana": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "katana"}]}},
    "hakrawler": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "hakrawler"}]}},
    "jsluice": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "jsluice"}]}},
    "zap_ajax_spider": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "zap_ajax_spider"}]}},
    "ffuf": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "ffuf"}]}},
    "arjun": {"resource_enum": {"external_domains": [{**_ENTRY, "source": "arjun"}]}},
    "http_probe_redirect": {"http_probe": {"external_domains": [{**_ENTRY, "source": "http_probe_redirect"}]}},
    "urlscan_redirect": {"urlscan": {"external_domains": [{**_ENTRY, "source": "urlscan_redirect"}]}},
    "js_recon": {"js_recon": {"external_domains": [{"domain": UNLISTED}]}},
    "domain_discovery": {"domain_discovery_external_domains": [{**_ENTRY, "source": "cert_discovery"}]},
}


@pytest.mark.parametrize("source", sorted(SOURCES))
def test_no_source_of_the_aggregate_mints_a_subdomain(source):
    session = _write(_aggregated(_group(**SOURCES[source])))

    assert _minted(session) == set(), source
    assert _lookups(session) == {UNLISTED: ROOT}
    assert _externals(session) == []


def test_an_exact_groups_unlisted_name_is_no_subdomain():
    recon = _group(resource_enum={"external_domains": [{**_ENTRY, "source": "katana"}]})
    recon["metadata"]["scope_mode"] = "exact"
    recon["metadata"]["subdomain_filter"] = [KEPT]

    assert _minted(_write(_aggregated(recon))) == set()


# --------------------------------------------------------------------------- #
# A Domain batch: a host under a sibling scan root
# --------------------------------------------------------------------------- #
def test_a_sibling_roots_host_is_looked_up_under_its_org_and_never_minted():
    recon = _group(all_project_roots=[ROOT, SIBLING_ROOT],
                   resource_enum={"external_domains": [
                       {"domain": SIBLING_HOST, "source": "katana", "url": f"https://{SIBLING_HOST}/"},
                       {"domain": SIBLING_ROOT, "source": "katana", "url": f"https://{SIBLING_ROOT}/"},
                       {"domain": FOREIGN, "source": "katana", "url": f"https://{FOREIGN}/"}]})
    session = _write(_aggregated(recon))

    assert _minted(session) == set()
    assert _lookups(session) == {SIBLING_HOST: SIBLING_ROOT}
    assert _externals(session) == [FOREIGN]


# --------------------------------------------------------------------------- #
# IP mode keeps its own rule: a name the hostname rule selected
# --------------------------------------------------------------------------- #
def test_ip_mode_still_writes_a_selected_name_under_its_org():
    mock_root = "ip-targets.projcrawllink"
    recon = {"domain": mock_root,
             "subdomains": ["192-0-2-10", "app.example.com"],
             "metadata": {"ip_mode": True, "root_domain": mock_root, "expanded_ips": ["192.0.2.10"],
                          "ip_mode_hosts": {"app.example.com": ROOT}},
             "http_probe": {"external_domains": [
                 {"domain": "app.example.com", "source": "http_probe_redirect",
                  "redirect_from_url": "https://192.0.2.10/"},
                 {"domain": "old.example.com", "source": "http_probe_redirect",
                  "redirect_from_url": "https://192.0.2.10/"}]}}
    session = _write(_aggregated(recon))

    assert _minted(session) == {"app.example.com"}
    (cypher, params), = [(c, p) for c, p in session.calls if _MINT.search(c)]
    assert "MERGE (s:Subdomain {name: $name, user_id: $uid, project_id: $pid})" in cypher
    assert "ON CREATE SET s.source = $source" in cypher
    assert (params["domain"], params["source"]) == (ROOT, "http_probe_redirect")
    assert _externals(session) == ["old.example.com"]
