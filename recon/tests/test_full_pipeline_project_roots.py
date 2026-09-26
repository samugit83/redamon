"""The full pipeline hands the whole batch's roots to the graph writers.

run_domain_group scans one group at a time, so recon_data["domain"] is the group
root. _stamp_project_roots adds recon_data["all_project_roots"] (every batch
root) so the writers attach a cross-root host to the right root. It is NOT
"domains", which would widen the per-group scan scope. A single-domain project
gets no such key.

Fixture roots are alpha.test / beta.test / gamma.test only.
"""
import sys
from pathlib import Path

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import recon.main as main  # noqa: E402

ROOTS = ["alpha.test", "beta.test", "gamma.test"]
BATCH = {
    "DOMAIN_BATCH_MODE": True,
    "DOMAIN_BATCH_GROUPS": [{"rootDomain": r, "prefixes": ["*"]} for r in ROOTS],
}


@pytest.fixture
def batch_settings(monkeypatch):
    monkeypatch.setattr(main, "_settings", dict(BATCH))
    monkeypatch.setattr(main, "VERIFY_DOMAIN_OWNERSHIP", False)
    monkeypatch.setattr(main, "_BATCH_ATTACH_ROOTS", main._eligible_batch_roots(BATCH["DOMAIN_BATCH_GROUPS"]))


@pytest.fixture
def single_settings(monkeypatch):
    monkeypatch.setattr(main, "_settings", {"DOMAIN_BATCH_MODE": False})


def test_every_scanned_root_is_attachable(batch_settings):
    assert main._eligible_batch_roots(BATCH["DOMAIN_BATCH_GROUPS"]) == ROOTS


def test_a_refused_root_is_not_attachable_or_seeded(monkeypatch):
    """Bug: all_project_roots and the Domain seeding took EVERY batch root, so a
    host found under a root the group run refuses (RoE-excluded, or failing
    ownership) became an in-scope Subdomain instead of an ExternalDomain."""
    settings = dict(BATCH, ROE_ENABLED=True, ROE_EXCLUDED_HOSTS=["beta.test"])
    monkeypatch.setattr(main, "_settings", settings)
    monkeypatch.setattr(main, "VERIFY_DOMAIN_OWNERSHIP", True)
    monkeypatch.setattr(main, "verify_domain_ownership",
                        lambda root, token, prefix: {"verified": root != "gamma.test"})
    assert main._eligible_batch_roots(BATCH["DOMAIN_BATCH_GROUPS"]) == ["alpha.test"]


def test_an_ownership_check_that_errors_fails_closed(monkeypatch):
    monkeypatch.setattr(main, "_settings", dict(BATCH))
    monkeypatch.setattr(main, "VERIFY_DOMAIN_OWNERSHIP", True)

    def boom(*a):
        raise OSError("dns down")

    monkeypatch.setattr(main, "verify_domain_ownership", boom)
    assert main._eligible_batch_roots(BATCH["DOMAIN_BATCH_GROUPS"]) == []


def test_stamp_adds_all_project_roots_in_batch_mode(batch_settings):
    recon_data = {"domain": "alpha.test"}
    main._stamp_project_roots(recon_data)
    assert recon_data["all_project_roots"] == ROOTS
    # The scan scope stays the group root: "domains" is never set here.
    assert "domains" not in recon_data


def test_stamp_is_a_noop_for_a_single_domain_project(single_settings):
    recon_data = {"domain": "alpha.test"}
    main._stamp_project_roots(recon_data)
    assert "all_project_roots" not in recon_data


def test_stamp_returns_the_same_dict(batch_settings):
    recon_data = {"domain": "alpha.test"}
    assert main._stamp_project_roots(recon_data) is recon_data


def _graph_module(monkeypatch, client):
    from unittest.mock import MagicMock
    client.__enter__ = MagicMock(return_value=client)
    client.__exit__ = MagicMock(return_value=False)
    module = MagicMock()
    module.Neo4jClient.return_value = client
    monkeypatch.setitem(sys.modules, "graph_db", module)


def test_the_batch_restores_every_roots_domain_node_before_group_1(monkeypatch):
    from unittest.mock import MagicMock
    client = MagicMock()
    client.verify_connection.return_value = True
    client.ensure_root_domains.return_value = 3
    _graph_module(monkeypatch, client)
    monkeypatch.setattr(main, "UPDATE_GRAPH_DB", True)
    monkeypatch.setattr(main, "USER_ID", "u1")
    monkeypatch.setattr(main, "PROJECT_ID", "p1")
    main._seed_batch_root_domains(ROOTS)
    client.ensure_root_domains.assert_called_once_with(ROOTS, "u1", "p1")


def test_a_seeding_failure_never_fails_the_scan(monkeypatch):
    from unittest.mock import MagicMock
    client = MagicMock()
    client.verify_connection.return_value = True
    client.ensure_root_domains.side_effect = RuntimeError("neo4j down")
    _graph_module(monkeypatch, client)
    monkeypatch.setattr(main, "UPDATE_GRAPH_DB", True)
    main._seed_batch_root_domains(ROOTS)   # must not raise


def test_seeding_happens_before_the_first_group(monkeypatch, tmp_path):
    order = []
    monkeypatch.setattr(main, "_settings", dict(BATCH))
    monkeypatch.setattr(main, "VERIFY_DOMAIN_OWNERSHIP", False)
    monkeypatch.setattr(main, "_seed_batch_root_domains", lambda roots: order.append(("seed", roots)))
    monkeypatch.setattr(main, "run_domain_group",
                        lambda root, prefixes, start_time=None, openapi_pacer=None: order.append(root) or 0)
    monkeypatch.setattr(main, "OUTPUT_DIR", tmp_path)
    monkeypatch.setattr(main, "merge_batch_outputs", lambda *a, **k: None)
    from datetime import datetime
    main.run_domain_batch(BATCH["DOMAIN_BATCH_GROUPS"], start_time=datetime.now())
    assert order == [("seed", ROOTS)] + ROOTS
