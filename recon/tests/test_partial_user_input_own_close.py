"""A completed partial run leaves none of its own UserInput nodes 'running' (L-11).

create_user_input_node writes status 'running'; only the module that made the
node sets its final status, and not every module or path does (cache, GraphQL,
serialized and tlsx write none), so a node kept for its results could read
'running' forever. The end-of-run cleanup, which runs only after
the tool returned, now marks this run's own surviving nodes still 'running' as
completed. It never touches a status the module set, another run's node (it may
still be scanning), or a node of another project with the same id.

The graph is an in-memory stand-in that answers the three statements the
cleanup issues; the Cypher itself runs against Neo4j in
test_partial_user_input_own_close_live.py.
"""
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

import graph_db  # noqa: E402
from graph_db.mixins.recon import user_input_mixin as uim  # noqa: E402
from recon.partial_recon_modules import user_inputs  # noqa: E402

UID, PID, OTHER_PID = "u1", "p1", "p2"


class _Graph:
    """Nodes keyed (id, user_id, project_id) -> {status, linked, completed_at}.

    Answers the orphan read, the delete and the close; any other statement
    fails the test, so a new write cannot slip in unseen."""

    def __init__(self, nodes):
        self.nodes = {k: dict(v) for k, v in nodes.items()}
        self.calls = []
        session = MagicMock()
        session.__enter__ = MagicMock(return_value=session)
        session.__exit__ = MagicMock(return_value=False)
        session.run.side_effect = self._run
        self.driver = MagicMock()
        self.driver.session.return_value = session

    def _tenant(self, params):
        return [k for k in self.nodes if k[1:] == (params["uid"], params["pid"])]

    def _run(self, query, **params):
        self.calls.append((query, params))
        result = MagicMock()
        if "DETACH DELETE" in query:
            gone = [k for k in self._tenant(params)
                    if k[0] in params["ids"] and not self.nodes[k]["linked"]]
            for k in gone:
                del self.nodes[k]
            result.single.return_value = {"deleted": len(gone)}
        elif "SET" in query:
            closed = [k for k in self._tenant(params)
                      if k[0] in params["ids"] and self.nodes[k]["status"] == "running"]
            for k in closed:
                self.nodes[k].update(status="completed", completed_at="now")
            result.single.return_value = {"closed": len(closed)}
        elif "RETURN ui.id AS id, ui.status AS status" in query:
            rows = [{"id": k[0], "status": self.nodes[k]["status"]}
                    for k in self._tenant(params) if not self.nodes[k]["linked"]]
            result.__iter__ = MagicMock(return_value=iter(rows))
        else:
            raise AssertionError(f"unexpected statement: {query}")
        return result

    def writes(self, word):
        return [c for c in self.calls if word in c[0]]

    def status(self, ui_id, pid=PID):
        node = self.nodes.get((ui_id, UID, pid))
        return node and node["status"]

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def verify_connection(self):
        return True


def _node(status, linked, completed_at=None):
    return {"status": status, "linked": linked, "completed_at": completed_at}


def _cleanup(graph, own):
    with patch.object(uim, "_CREATED_THIS_RUN", set(own)), \
            patch.object(graph_db, "Neo4jClient", return_value=graph):
        return user_inputs._cleanup_orphan_user_inputs(UID, PID)


def test_own_node_with_results_reads_completed():
    # A module that links results but never sets a status: no orphan to
    # delete at all, so nothing else in the cleanup touches the graph.
    graph = _Graph({("ui-own", UID, PID): _node("running", linked=True)})
    assert _cleanup(graph, {"ui-own"}) == 0
    assert graph.status("ui-own") == "completed"
    assert graph.nodes[("ui-own", UID, PID)]["completed_at"] == "now"


def test_another_runs_node_stays_running():
    # A concurrent httpx run links its results before it sets its status.
    graph = _Graph({
        ("ui-own", UID, PID): _node("running", linked=True),
        ("ui-other", UID, PID): _node("running", linked=True),
        ("ui-other-orphan", UID, PID): _node("running", linked=False),
    })
    _cleanup(graph, {"ui-own"})
    assert graph.status("ui-own") == "completed"
    assert graph.status("ui-other") == "running"
    assert graph.status("ui-other-orphan") == "running"


def test_a_status_the_module_set_is_kept():
    graph = _Graph({
        ("ui-failed", UID, PID): _node("error", linked=True),
        ("ui-done", UID, PID): _node("completed", linked=True, completed_at="module"),
    })
    _cleanup(graph, {"ui-failed", "ui-done"})
    assert graph.status("ui-failed") == "error"
    assert graph.nodes[("ui-done", UID, PID)]["completed_at"] == "module"


def test_the_same_id_in_another_project_is_untouched():
    graph = _Graph({
        ("ui-own", UID, PID): _node("running", linked=True),
        ("ui-own", UID, OTHER_PID): _node("running", linked=True),
    })
    _cleanup(graph, {"ui-own"})
    assert graph.status("ui-own") == "completed"
    assert graph.status("ui-own", OTHER_PID) == "running"


def test_own_orphan_is_deleted_and_own_linked_closed():
    graph = _Graph({
        ("ui-own-empty", UID, PID): _node("running", linked=False),
        ("ui-own-found", UID, PID): _node("running", linked=True),
    })
    assert _cleanup(graph, {"ui-own-empty", "ui-own-found"}) == 1
    assert ("ui-own-empty", UID, PID) not in graph.nodes
    assert graph.status("ui-own-found") == "completed"
    # The delete runs first: an orphan is deleted, never closed and kept.
    kinds = ["delete" if "DETACH DELETE" in q else "close" if "SET" in q else "read"
             for q, _ in graph.calls]
    assert kinds == ["read", "delete", "close"]


def test_the_close_matches_the_tenant_the_own_ids_and_running_only():
    graph = _Graph({("ui-own", UID, PID): _node("running", linked=True)})
    _cleanup(graph, {"ui-own"})
    (query, params), = graph.writes("SET")
    assert "UserInput {user_id: $uid, project_id: $pid}" in query
    assert "ui.id IN $ids" in query
    assert "ui.status = 'running'" in query
    assert "ui.completed_at = datetime()" in query
    assert params == {"uid": UID, "pid": PID, "ids": ["ui-own"]}


def test_a_run_that_made_no_node_writes_nothing():
    graph = _Graph({("ui-other", UID, PID): _node("running", linked=True)})
    assert _cleanup(graph, set()) == 0
    assert graph.writes("SET") == []
    assert graph.status("ui-other") == "running"


def test_a_failing_close_never_fails_the_run():
    graph = _Graph({("ui-own", UID, PID): _node("running", linked=True)})
    real_run = graph._run

    def run(query, **params):
        if "SET" in query:
            raise RuntimeError("graph went away")
        return real_run(query, **params)

    graph.driver.session.return_value.run.side_effect = run
    assert _cleanup(graph, {"ui-own"}) == 0


@pytest.mark.parametrize("status", ["running", "completed", "error"])
def test_the_close_only_selects_running(status):
    graph = _Graph({("ui-own", UID, PID): _node(status, linked=True)})
    _cleanup(graph, {"ui-own"})
    assert graph.status("ui-own") == ("completed" if status == "running" else status)
