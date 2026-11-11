"""The end-of-run UserInput cleanup never deletes a concurrent run's node (L-11).

Up to twelve partial runs of one project can run at once. Httpx creates its
UserInput for typed IPs BEFORE it scans, and links what it found only after; the
cleanup at the end of any other run deleted every UserInput with no outgoing
edge, so it deleted that node mid-scan and the run's results were never linked.

An orphan is now deleted only when no live run can still link it: this run made
it (graph_db's create_user_input_node records the ids it made in this process),
or its run has finished (status 'completed' or 'error', which every caller sets
after writing the node's edges). A 'running' node another run made is kept.

The status update is what makes "finished" readable at all: it matched nothing
until it was given the tenant, so every caller must pass user_id and project_id
(the writer itself is tested in tests/test_user_input_status_writer.py).

Reserved names and documentation addresses only.
"""
import ast
import os
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import graph_db  # noqa: E402
from graph_db.mixins.recon import user_input_mixin as uim  # noqa: E402
from recon.partial_recon_modules import user_inputs  # noqa: E402

MODULES_DIR = PROJECT_ROOT / "recon" / "partial_recon_modules"

OWN_RUNNING = {"id": "ui-own-running", "status": "running"}            # this run, nothing found
OTHER_RUNNING = {"id": "ui-other-running", "status": "running"}        # a concurrent httpx run mid-scan
OTHER_COMPLETED = {"id": "ui-other-completed", "status": "completed"}  # a finished run, nothing linked
OTHER_ERROR = {"id": "ui-other-error", "status": "error"}              # a failed run
UNTRACKED = {"id": "ui-untracked", "status": None}                     # a writer that sets no status


class _Graph:
    """A Neo4jClient stand-in: answers the orphan read with `orphans` and
    records the delete."""

    def __init__(self, orphans, deleted=None):
        self.orphans = orphans
        self.deleted = deleted
        self.calls = []
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        session.run.side_effect = self._run
        self.driver = MagicMock()
        self.driver.session.return_value = session

    def _run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        if "DETACH DELETE" in query:
            n = len(params["ids"]) if self.deleted is None else self.deleted
            result.single.return_value = {"deleted": n}
        else:
            result.__iter__ = MagicMock(return_value=iter(self.orphans))
        return result

    def deletes(self):
        return [c for c in self.calls if "DETACH DELETE" in c[0]]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True


@pytest.fixture
def own_ids(monkeypatch):
    monkeypatch.setattr(uim, "_CREATED_THIS_RUN", {OWN_RUNNING["id"]})


def _cleanup(graph):
    with patch.object(graph_db, "Neo4jClient", return_value=graph):
        return user_inputs._cleanup_orphan_user_inputs("u1", "p1")


def test_a_concurrent_runs_running_node_survives(own_ids):
    graph = _Graph([OWN_RUNNING, OTHER_RUNNING, OTHER_COMPLETED, OTHER_ERROR, UNTRACKED])
    assert _cleanup(graph) == 3
    (query, params), = graph.deletes()
    assert params["ids"] == sorted([OWN_RUNNING["id"], OTHER_COMPLETED["id"], OTHER_ERROR["id"]])
    assert OTHER_RUNNING["id"] not in params["ids"]
    assert UNTRACKED["id"] not in params["ids"]
    assert (params["uid"], params["pid"]) == ("u1", "p1")


def test_the_delete_rechecks_the_tenant_and_the_missing_edge():
    # A run may link its node between the read and the delete: the delete
    # must find it childless again, inside the same project.
    graph = _Graph([OTHER_COMPLETED])
    _cleanup(graph)
    (query, params), = graph.deletes()
    assert "UserInput {user_id: $uid, project_id: $pid}" in query
    assert "NOT (ui)-->()" in query
    assert "ui.id IN $ids" in query


def test_the_orphan_read_is_scoped_to_the_project():
    graph = _Graph([])
    _cleanup(graph)
    (query, params), = graph.calls
    assert "UserInput {user_id: $uid, project_id: $pid}" in query
    assert (params["uid"], params["pid"]) == ("u1", "p1")


def test_nothing_to_delete_runs_no_delete(own_ids):
    graph = _Graph([OTHER_RUNNING, UNTRACKED])
    assert _cleanup(graph) == 0
    assert graph.deletes() == []


def test_the_count_is_what_the_delete_removed(own_ids):
    # An orphan that gained an edge in between is not deleted, nor counted.
    graph = _Graph([OWN_RUNNING, OTHER_COMPLETED], deleted=1)
    assert _cleanup(graph) == 1


def test_a_graph_error_never_fails_the_run():
    with patch.object(graph_db, "Neo4jClient", side_effect=RuntimeError("down")):
        assert user_inputs._cleanup_orphan_user_inputs("u1", "p1") == 0


@pytest.mark.parametrize("row,own,expected", [
    (OWN_RUNNING, {"ui-own-running"}, True),
    (OTHER_RUNNING, {"ui-own-running"}, False),
    (OTHER_COMPLETED, set(), True),
    (OTHER_ERROR, set(), True),
    (UNTRACKED, set(), False),
    (UNTRACKED, {"ui-untracked"}, True),
])
def test_which_orphans_no_run_can_still_link(row, own, expected):
    assert (row["id"] in user_inputs._orphans_no_run_will_link([row], own)) is expected


# -- every caller gives the status update its tenant --------------------------

def _status_update_calls():
    for path in sorted(MODULES_DIR.glob("*.py")):
        tree = ast.parse(path.read_text(), filename=str(path))
        for node in ast.walk(tree):
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "update_user_input_status"):
                yield path.name, node


def test_the_status_update_has_callers():
    # The scan below proves nothing if the call was renamed away.
    assert len(list(_status_update_calls())) >= 9


@pytest.mark.parametrize("where,call", [
    pytest.param(name, node, id=f"{name}:{node.lineno}") for name, node in _status_update_calls()
])
def test_every_status_update_passes_the_tenant(where, call):
    kwargs = {k.arg: k.value for k in call.keywords}
    assert isinstance(kwargs.get("user_id"), ast.Name) and kwargs["user_id"].id == "user_id", where
    assert isinstance(kwargs.get("project_id"), ast.Name) and kwargs["project_id"].id == "project_id", where


def test_route_exposure_marks_its_user_input_completed_in_its_project():
    import recon.partial_recon_modules.route_exposure_scanning as rx
    client = MagicMock()
    client.link_route_exposure_user_input.return_value = 1
    finding = {"baseurl": "http://192.0.2.10", "path": "/a", "exposure_kind": "env_file"}
    rx._link_user_urls(client, ["http://192.0.2.10/x"], None, ["ip-targets.p1"], "u1", "p1", [finding])
    ui_id = client.create_user_input_node.call_args.kwargs["user_input_data"]["id"]
    client.update_user_input_status.assert_called_once_with(
        ui_id, "completed", {"findings": 1}, user_id="u1", project_id="p1")


def test_openapi_marks_its_user_input_completed_in_its_project():
    import recon.partial_recon_modules.openapi_recon as oa
    client = MagicMock()
    oa._link_user_input(client, ["example.com"], "u1", "p1", ["https://example.com/openapi.json"],
                        {("https://example.com", "/pets", "GET")},
                        {"endpoints_created": 1, "parameters_created": 0})
    ui_id = client.create_user_input_node.call_args.kwargs["user_input_data"]["id"]
    client.update_user_input_status.assert_called_once_with(
        ui_id, "completed", {"endpoints_created": 1, "parameters_created": 0},
        user_id="u1", project_id="p1")
