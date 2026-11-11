"""graph_db: a partial run's UserInput status update reaches its node (L-11).

The node's key is {id, user_id, project_id} (graph_db/schema_keys.py). The
update matched `{user_id: $props.user_id, project_id: $props.project_id}`, but
`props` carried neither key, so both compared with null, nothing matched and
every UserInput read 'running' forever. The caller's tenant now reaches the
MATCH as parameters, and a miss is reported instead of passing silently.

create_user_input_node also records the ids it made in this process (one
partial run is one container process), so the end-of-run orphan cleanup can
tell its own nodes from a concurrent run's (recon/tests/test_partial_user_input_cleanup.py).

Run with:
    python3 -m pytest tests/test_user_input_status_writer.py -v
"""
import datetime as _dt
import json
import os
import re
import sys
import unittest

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.mixins.recon import user_input_mixin as uim  # noqa: E402
from graph_db.mixins.recon.domain_mixin import DomainMixin  # noqa: E402
from graph_db.mixins.recon.user_input_mixin import UserInputMixin  # noqa: E402

_USER_INPUT_MATCH = re.compile(r"MATCH \(ui:UserInput \{([^}]*)\}\)")


class _Result:
    def __init__(self, record):
        self._record = record

    def single(self):
        return self._record


class _Session:
    """Records every run(query, **params); answers `matched` for the status update."""

    def __init__(self, matched=1):
        self.calls = []
        self.matched = matched

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        if "RETURN count(ui) AS matched" in query:
            return _Result({"matched": self.matched})
        return _Result({"seeded": 1})


class _Driver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class _Client(DomainMixin, UserInputMixin):
    def __init__(self, matched=1):
        self.session = _Session(matched)
        self.driver = _Driver(self.session)

    def status_call(self):
        calls = [c for c in self.session.calls if _USER_INPUT_MATCH.search(c[0]) and " SET " in f" {c[0]} "]
        assert len(calls) == 1, calls
        return calls[0]


def _resolved_key(query: str, params: dict) -> dict:
    """The UserInput MATCH map with every `$param` / `$param.key` resolved
    against what the writer passed, as Neo4j would resolve it."""
    body = _USER_INPUT_MATCH.search(query).group(1)
    key = {}
    for part in body.split(","):
        name, expr = (s.strip() for s in part.split(":", 1))
        assert expr.startswith("$"), f"{name} is not a parameter: {expr}"
        value = params
        for step in expr[1:].split("."):
            value = value.get(step) if isinstance(value, dict) else None
        key[name] = value
    return key


class TestUpdateUserInputStatus(unittest.TestCase):
    def test_the_match_key_is_the_callers_tenant(self):
        c = _Client()
        c.update_user_input_status("ui-1", "completed", {"probed": 2}, user_id="u1", project_id="p1")
        query, params = c.status_call()
        self.assertEqual(_resolved_key(query, params),
                         {"id": "ui-1", "user_id": "u1", "project_id": "p1"})

    def test_the_tenant_is_required(self):
        # A call without it would match {user_id: null}: nothing, silently.
        with self.assertRaises(TypeError):
            _Client().update_user_input_status("ui-1", "completed", {})

    def test_completed_writes_the_status_the_stats_and_completed_at(self):
        c = _Client()
        self.assertTrue(c.update_user_input_status(
            "ui-1", "completed", {"probed": 2}, user_id="u1", project_id="p1"))
        query, params = c.status_call()
        self.assertEqual(params["props"]["status"], "completed")
        self.assertEqual(json.loads(params["props"]["stats"]), {"probed": 2})
        self.assertIn("ui.completed_at = datetime()", query)
        self.assertIn("ui.updated_at = datetime()", query)

    def test_an_error_status_does_not_claim_completion(self):
        c = _Client()
        c.update_user_input_status("ui-1", "error", {"error": "boom"}, user_id="u1", project_id="p1")
        query, params = c.status_call()
        self.assertEqual(params["props"]["status"], "error")
        self.assertNotIn("completed_at", query)

    def test_no_stats_leaves_the_stored_stats_alone(self):
        c = _Client()
        c.update_user_input_status("ui-1", "completed", None, user_id="u1", project_id="p1")
        _, params = c.status_call()
        self.assertNotIn("stats", params["props"])

    def test_stats_that_json_cannot_encode_are_stringified(self):
        # Callers print the same stats with default=str: they can hold datetimes.
        c = _Client()
        when = _dt.datetime(2026, 1, 2, 3, 4, 5)
        c.update_user_input_status("ui-1", "completed", {"at": when}, user_id="u1", project_id="p1")
        _, params = c.status_call()
        self.assertEqual(json.loads(params["props"]["stats"]), {"at": str(when)})

    def test_a_miss_returns_false_and_says_so(self):
        c = _Client(matched=0)
        from io import StringIO
        from contextlib import redirect_stdout
        out = StringIO()
        with redirect_stdout(out):
            self.assertFalse(c.update_user_input_status(
                "ui-gone", "completed", None, user_id="u1", project_id="p1"))
        self.assertIn("ui-gone", out.getvalue())


class TestCreatedThisRun(unittest.TestCase):
    def setUp(self):
        self._saved = set(uim._CREATED_THIS_RUN)
        uim._CREATED_THIS_RUN.clear()

    def tearDown(self):
        uim._CREATED_THIS_RUN.clear()
        uim._CREATED_THIS_RUN.update(self._saved)

    def test_create_records_the_id_as_this_runs(self):
        c = _Client()
        c.create_user_input_node("alpha.test", {"id": "ui-mine", "input_type": "ips",
                                                "values": ["192.0.2.10"], "tool_id": "Httpx"},
                                 "u1", "p1")
        self.assertEqual(uim.user_inputs_created_this_run(), frozenset({"ui-mine"}))

    def test_a_refused_create_records_nothing(self):
        with self.assertRaises(ValueError):
            _Client().create_user_input_node("", {"id": "ui-x", "values": []}, "u1", "p1")
        self.assertEqual(uim.user_inputs_created_this_run(), frozenset())


if __name__ == "__main__":
    unittest.main()
