"""An RoE-excluded host never reaches the graph through Uncover (D2).

merge_uncover_into_pipeline removes from the payload's ``hosts`` every name its
gates refuse (group scope, RoE, syntax, non-routable address, wildcard DNS),
and both the full pipeline and partial Uncover run it before
update_graph_from_uncover. A search-engine URL kept its host, though, and the
writer minted a Subdomain for every URL host: an RoE-excluded name came back as
a Subdomain, and partial Naabu, httpx and Nuclei read their targets from the
graph.

- The merge drops a URL whose host its gates refused or the RoE excludes, in an
  ENUMERATE and an EXACT group, so such a host gets no BaseURL or Endpoint.
- The writer never mints a Subdomain from a URL: a URL's BaseURL joins the
  Subdomain already in the graph, or the Domain.

The real merge and the real writer run; DNS and Neo4j are the fakes (an empty
graph). Only example.com names and the special-purpose addresses the
non-routable gate is about are used.
"""
from __future__ import annotations

import socket
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.osint_mixin import OsintMixin  # noqa: E402
from recon.main_recon_modules.uncover_enrich import merge_uncover_into_pipeline  # noqa: E402

ROOT = "example.com"
KEPT = "api.example.com"
EXCLUDED = "shop.example.com"
# Resolves to the cloud-metadata address: the non-routable gate refuses it.
METADATA = "meta.example.com"
ROE = {"ROE_ENABLED": True, "ROE_EXCLUDED_HOSTS": [EXCLUDED]}
PID = "proj-uncover-roe"


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
        result.single.return_value = None
        result.__iter__ = lambda _s: iter([])
        return result


def _writer():
    session = _Session()
    writer = OsintMixin()
    writer.driver = MagicMock()
    writer.driver.session.return_value = session
    return writer, session


def _minted(session) -> set:
    """Every name a statement may create a Subdomain node for."""
    return {params.get("name") or params.get("host")
            for cypher, params in session.calls if "MERGE (s:Subdomain" in cypher}


def _domain_owned_base_urls(session) -> set:
    return {params.get("base_url") for cypher, params in session.calls
            if "(d:Domain" in cypher and "HAS_BASE_URL" in cypher}


def _named(session, name: str) -> list:
    """Every statement with a parameter naming ``name`` (a host, a URL)."""
    return [cypher for cypher, params in session.calls
            if any(isinstance(v, str) and name in v for v in params.values())]


def _payload() -> dict:
    return {"hosts": [KEPT, EXCLUDED], "ips": [], "ip_ports": {},
            "urls": [f"https://{KEPT}/login", f"https://{EXCLUDED}/cart"],
            "sources": ["shodan"], "source_counts": {"shodan": 2},
            "total_raw": 2, "total_deduped": 2}


@pytest.fixture(autouse=True)
def _dns(monkeypatch):
    """The merge resolves each name and probes its zone for wildcard DNS."""
    from recon.helpers import circuit_breaker, wildcard_control

    def getaddrinfo(host, *_a, **_k):
        if host == METADATA:
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]
        raise socket.gaierror(socket.EAI_NONAME, "unknown name")

    monkeypatch.setattr(socket, "getaddrinfo", getaddrinfo)
    monkeypatch.setattr(wildcard_control, "_query", lambda name, rtype: ("nx", []))
    circuit_breaker.reset_registry()
    yield
    circuit_breaker.reset_registry()


def _group_recon(mode: str, exact_hosts=()) -> dict:
    """What run_domain_recon holds for one scope group at GROUP 2b."""
    return {"domain": ROOT, "dns": {"domain": {}, "subdomains": {}},
            "metadata": {"root_domain": ROOT, "org_domain": ROOT, "scope_mode": mode,
                         "include_root_domain": False, "subdomain_filter": list(exact_hosts)}}


def _full_run(combined: dict, settings: dict, payload=None):
    payload = payload or _payload()
    merge_uncover_into_pipeline(combined, payload, ROOT, settings=settings)
    combined["uncover"] = payload
    writer, session = _writer()
    stats = writer.update_graph_from_uncover(combined, "u1", PID)
    return payload, session, stats


# --------------------------------------------------------------------------- #
# Full pipeline
# --------------------------------------------------------------------------- #
def test_an_enumerate_group_writes_nothing_for_an_excluded_host():
    payload, session, stats = _full_run(_group_recon("enumerate"), ROE)

    assert payload["hosts"] == [KEPT]
    assert payload["urls"] == [f"https://{KEPT}/login"]
    assert _named(session, EXCLUDED) == []
    assert KEPT in _minted(session)
    assert stats["urls_created"] == 1
    assert stats["errors"] == []


def test_an_exact_group_writes_nothing_for_an_excluded_listed_host():
    # An EXACT group keeps a URL on a listed host and no discovered name at
    # all; the RoE still wins over the operator's list.
    payload, session, stats = _full_run(_group_recon("exact", exact_hosts=[KEPT, EXCLUDED]), ROE)

    assert payload["hosts"] == []
    assert payload["urls"] == [f"https://{KEPT}/login"]
    assert _named(session, EXCLUDED) == []
    assert stats["urls_created"] == 1
    assert stats["errors"] == []


def test_an_exact_group_without_an_roe_keeps_every_listed_host_url():
    payload, _session, _stats = _full_run(_group_recon("exact", exact_hosts=[KEPT, EXCLUDED]), {})

    assert payload["urls"] == [f"https://{KEPT}/login", f"https://{EXCLUDED}/cart"]


def test_without_an_roe_exclusion_both_hosts_are_subdomains():
    payload, session, stats = _full_run(_group_recon("enumerate"), {})

    assert payload["hosts"] == [KEPT, EXCLUDED]
    assert payload["urls"] == [f"https://{KEPT}/login", f"https://{EXCLUDED}/cart"]
    assert {KEPT, EXCLUDED} <= _minted(session)
    assert stats["urls_created"] == 2


def test_the_url_of_a_name_another_gate_refused_is_dropped():
    payload = {**_payload(), "hosts": [KEPT, METADATA],
               "urls": [f"https://{KEPT}/login", f"https://{METADATA}/latest"]}
    payload, session, _stats = _full_run(_group_recon("enumerate"), {}, payload)

    assert payload["hosts"] == [KEPT]
    assert payload["urls"] == [f"https://{KEPT}/login"]
    assert _named(session, METADATA) == []


def test_an_excluded_url_host_the_payload_never_named_is_dropped():
    # A row whose url names another host than its host field.
    payload = {**_payload(), "hosts": [KEPT]}
    payload, session, _stats = _full_run(_group_recon("enumerate"), ROE, payload)

    assert payload["urls"] == [f"https://{KEPT}/login"]
    assert _named(session, EXCLUDED) == []


def test_a_host_already_in_the_dns_map_keeps_its_url():
    # Discovery admitted it, so the merge does not gate it again.
    combined = _group_recon("enumerate")
    combined["dns"]["subdomains"][KEPT] = {"ips": {"ipv4": []}}
    payload = {**_payload(), "hosts": [KEPT], "urls": [f"https://{KEPT}/login"]}
    payload, _session, _stats = _full_run(combined, ROE, payload)

    assert payload["urls"] == [f"https://{KEPT}/login"]


def test_a_url_host_the_payload_does_not_name_joins_no_new_subdomain():
    # A row whose url names another host than its host field: the url's host
    # never passed the merge's gates.
    combined = _group_recon("enumerate")
    combined["uncover"] = {"hosts": [KEPT], "ips": [], "ip_ports": {},
                           "urls": [f"https://{KEPT}/a", f"https://other.{ROOT}/b"]}
    writer, session = _writer()
    writer.update_graph_from_uncover(combined, "u1", PID)

    assert f"other.{ROOT}" not in _minted(session)
    assert KEPT in _minted(session)
    # A URL joins the Subdomain the host loop or another writer made: looked
    # up in its tenant, never created. In this empty graph it finds none.
    lookups = [params for cypher, params in session.calls
               if "MATCH (s:Subdomain" in cypher and "HAS_BASE_URL" in cypher]
    assert sorted(p["host"] for p in lookups) == [KEPT, f"other.{ROOT}"]
    assert all(p["user_id"] == "u1" and p["project_id"] == PID for p in lookups)
    assert f"https://other.{ROOT}" in _domain_owned_base_urls(session)


# --------------------------------------------------------------------------- #
# Partial Uncover
# --------------------------------------------------------------------------- #
def test_partial_uncover_writes_nothing_for_an_excluded_host(monkeypatch):
    import recon.partial_recon as pr
    from recon.partial_recon_modules import helpers, osint_enrichment

    monkeypatch.setattr(helpers.time, "sleep", lambda *_a, **_k: None)
    monkeypatch.setenv("USER_ID", "u1")
    monkeypatch.setenv("PROJECT_ID", PID)
    monkeypatch.delenv("WEBAPP_API_URL", raising=False)

    writer, session = _writer()
    client = MagicMock()
    client.verify_connection.return_value = True
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    client.update_graph_from_uncover.side_effect = writer.update_graph_from_uncover
    monkeypatch.setattr("graph_db.Neo4jClient", MagicMock(return_value=client))

    settings = {"TARGET_DOMAIN": ROOT, "IP_MODE": False, "DOMAIN_BATCH_MODE": False,
                "VERIFY_DOMAIN_OWNERSHIP": False, **ROE,
                "SCOPE_GROUPS": [{"scanRoot": ROOT, "orgDomain": ROOT, "mode": "enumerate",
                                  "includeRoot": False, "exactHosts": []}]}
    cfg = {"tool_id": "Uncover", "domains": [ROOT], "include_graph_targets": True}
    assert pr._prepare_scope(cfg, settings, PID) == {}

    with patch("recon.main_recon_modules.uncover_enrich.run_uncover_expansion",
               side_effect=lambda combined, settings: _payload()):
        statuses = osint_enrichment.run_uncover(cfg)

    assert statuses[ROOT] == "ok"
    assert _named(session, EXCLUDED) == []
    assert KEPT in _minted(session)
    assert any(f"https://{KEPT}" in (params.get("base_url") or "") for _c, params in session.calls)
