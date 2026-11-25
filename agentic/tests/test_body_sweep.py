"""The end of a run removes the route exposure bodies this session left in Kali.

A live AG4 switched skill and asked for the exploitation phase with a rejected
lead's two body files still in /tmp: the prompt's sweep rule was skipped. The
run's terminals (a phase request, a final answer) now sweep in code, removing
only the paths this session's own tool arguments named.

Run: ./agentic/run_tests.sh tests/test_body_sweep.py
"""

import asyncio
import inspect
from unittest import mock

import pytest

import sandbox_router
from orchestrator_helpers import body_sweep


@pytest.fixture
def running_sandbox():
    """The run holds its sandbox (the sweep then never asks the gateway)."""
    with mock.patch.object(sandbox_router, "current_handle", return_value=object()):
        yield


def _trace(*args_list):
    return [{"tool_name": "execute_curl", "tool_args": a} for a in args_list]


def test_only_concrete_paths_from_tool_arguments_are_collected():
    trace = _trace(
        {"args": "-s -o /tmp/rex-route_exposure_ab12-anon.body -w '%{http_code}' 'http://x/a'"},
        {"code": "import glob, os\nfor p in glob.glob('/tmp/rex-*'): os.remove(p)"},
        {"args": {"code": "OUT='/tmp/rex-git-route_exposure_ab12'\nREPORT=OUT+'.leaks.json'"}},
        {"args": "-o /tmp/rex-<id>-anon.body"},
    ) + [{"tool_name": "execute_code", "tool_args": None,
          "tool_output": "/tmp/rex-other-session.body"}]
    paths = body_sweep.session_body_paths(trace)
    assert "/tmp/rex-route_exposure_ab12-anon.body" in paths
    assert "/tmp/rex-git-route_exposure_ab12" in paths
    # A glob and a placeholder never become a wildcard, and output is not read.
    assert not any("*" in p or "<" in p for p in paths)
    assert "/tmp/rex-other-session.body" not in paths


class _Executor:
    def __init__(self, fail=False):
        self.calls, self.fail = [], fail

    async def execute(self, tool_name, tool_args, phase, skip_phase_check=False):
        self.calls.append((tool_name, tool_args, phase, skip_phase_check))
        if self.fail:
            raise RuntimeError("down")
        return {"success": True}


def test_the_sweep_removes_exactly_those_paths_quoted(running_sandbox):
    ex = _Executor()
    state = {"current_phase": "informational",
             "execution_trace": _trace({"args": "-o /tmp/rex-a.body"}, {"args": "-o /tmp/rex-b.body"})}
    assert asyncio.run(body_sweep.sweep_session_bodies(ex, state)) == 2
    [(tool, args, phase, skip)] = ex.calls
    assert tool == "kali_shell" and skip is True and phase == "informational"
    assert args["command"] == "rm -rf -- /tmp/rex-a.body /tmp/rex-b.body"


def test_no_paths_means_no_call_and_a_failure_never_raises(running_sandbox):
    ex = _Executor()
    assert asyncio.run(body_sweep.sweep_session_bodies(ex, {"execution_trace": []})) == 0
    assert ex.calls == []
    down = _Executor(fail=True)
    state = {"execution_trace": _trace({"args": "-o /tmp/rex-a.body"})}
    assert asyncio.run(body_sweep.sweep_session_bodies(down, state)) == 1


def test_both_run_terminals_sweep_before_they_run():
    import orchestrator
    src = inspect.getsource(orchestrator)
    for wrapper in ("_await_approval", "_generate_response"):
        body = src.split(f"async def {wrapper}(state, config=None):", 1)[1].split("async def", 1)[0]
        assert "await sweep_session_bodies(self.tool_executor, state)" in body, wrapper


def test_a_stopped_sandbox_is_never_started_to_sweep_it():
    """After the idle stop, a later message with no Kali step must not cold-start the
    sandbox (memory, a "starting" line) to delete files its stop already took with it."""
    ex = _Executor()
    state = {"execution_trace": _trace({"args": "-o /tmp/rex-a.body"})}
    running = mock.AsyncMock(return_value=False)
    with mock.patch.object(sandbox_router, "current_handle", return_value=None), \
            mock.patch.object(sandbox_router, "sandbox_user", return_value="bob"), \
            mock.patch.object(sandbox_router, "is_running", running):
        assert asyncio.run(body_sweep.sweep_session_bodies(ex, state)) == 0
    assert ex.calls == []
    running.assert_awaited_once_with("bob")


def test_a_running_sandbox_the_run_has_not_called_yet_is_swept():
    ex = _Executor()
    state = {"execution_trace": _trace({"args": "-o /tmp/rex-a.body"})}
    with mock.patch.object(sandbox_router, "current_handle", return_value=None), \
            mock.patch.object(sandbox_router, "sandbox_user", return_value="bob"), \
            mock.patch.object(sandbox_router, "is_running", mock.AsyncMock(return_value=True)):
        assert asyncio.run(body_sweep.sweep_session_bodies(ex, state)) == 1
    assert [c[0] for c in ex.calls] == ["kali_shell"]


def test_no_person_no_sweep():
    ex = _Executor()
    state = {"execution_trace": _trace({"args": "-o /tmp/rex-a.body"})}
    running = mock.AsyncMock(return_value=True)
    with mock.patch.object(sandbox_router, "current_handle", return_value=None), \
            mock.patch.object(sandbox_router, "sandbox_user", return_value=""), \
            mock.patch.object(sandbox_router, "is_running", running):
        assert asyncio.run(body_sweep.sweep_session_bodies(ex, state)) == 0
    assert ex.calls == [] and running.await_count == 0
