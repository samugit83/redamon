"""What a CodeFix failure tells the tab: a fixed sentence plus safe facts.

Before, a refused key, a 429 and an overflowing context all read "could not be
reached", a 401 from the webapp read "Remediation not found", and every clone
failure read the same whether the token, the repository or the branch was wrong.
The facts added here are codes, classes and integer statuses; the git stderr,
the GitHub body and the provider's message stay in the log.
"""
import asyncio
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cypherfix_codefix import orchestrator as module  # noqa: E402
from cypherfix_codefix.tools.github_repo import (  # noqa: E402
    GitCommandError, git_failure_cause)

LEAK = "ghp_LEAKEDTOKEN"


class _Callback:
    def __init__(self):
        self.errors = []
        self.phases = []

    async def on_error(self, message, recoverable=True, code="", **details):
        self.errors.append({"message": message, "code": code, **details})

    async def on_phase(self, phase, description):
        self.phases.append(phase)

    async def on_complete(self, *a, **k):
        pass

    async def on_pr_created(self, *a, **k):
        pass


def _orchestrator(callback=None):
    orch = module.CodeFixOrchestrator(module.CodeFixState(), callback or _Callback())
    orch.state.project_id = "p1"
    return orch


SETTINGS = {"github_repo": "acme/app", "model": "gpt-5", "settings_unavailable": False}


def _run(orch, remediation_loader):
    async def settings(_project_id):
        return dict(SETTINGS)

    async def no_update(*_a, **_k):
        return None

    orch._load_remediation = remediation_loader
    orch._update_remediation = no_update
    with mock.patch.object(module, "load_cypherfix_settings", settings):
        asyncio.run(orch.run("rem-1"))
    return orch.callback.errors


class _Response:
    def __init__(self, status_code, body=None):
        self.status_code = status_code
        self.is_success = 200 <= status_code < 300
        self._body = body

    def json(self):
        return self._body


class _Client:
    answer = None

    def __init__(self, *a, **k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False

    async def get(self, url, headers=None):
        if isinstance(_Client.answer, Exception):
            raise _Client.answer
        return _Client.answer


class TestTheRemediationLoad:
    def _load(self, answer):
        _Client.answer = answer
        with mock.patch.object(module.httpx, "AsyncClient", _Client):
            return asyncio.run(_orchestrator()._load_remediation("rem-1"))

    def test_a_404_is_a_missing_remediation(self):
        assert self._load(_Response(404)) is None

    def test_a_401_is_a_load_failure_with_its_status(self):
        with pytest.raises(module.RemediationLoadFailed) as failed:
            self._load(_Response(401, {"error": "Unauthorized"}))
        assert failed.value.details == {"upstream_status": 401}

    def test_a_transport_failure_names_its_class(self):
        with pytest.raises(module.RemediationLoadFailed) as failed:
            self._load(ConnectionError("http://webapp:3000 refused"))
        assert failed.value.details == {"error_class": "ConnectionError"}

    def test_the_tab_hears_load_failed_not_not_found(self):
        async def failing(_rid):
            raise module.RemediationLoadFailed({"upstream_status": 500})

        errors = _run(_orchestrator(), failing)
        assert errors[0]["code"] == "remediation_load_failed"
        assert errors[0]["upstream_status"] == 500
        assert errors[0]["message"] != "Remediation not found"

    def test_a_missing_one_keeps_its_text_and_gains_a_code(self):
        async def missing(_rid):
            return None

        errors = _run(_orchestrator(), missing)
        assert errors[0] == {"message": "Remediation not found", "code": "remediation_not_found"}


class TestTheClone:
    def test_a_clone_failure_names_the_step_exit_code_and_cause(self):
        class _Repo:
            def __init__(self, **_k):
                self.repo = "acme/app"

            def clone(self):
                raise GitCommandError(f"Clone failed: remote: Repository not found {LEAK}",
                                      128, "repo_not_found")

        async def found(_rid):
            return {"projectId": "p1", "title": "t"}

        with mock.patch.object(module, "GitHubRepoManager", _Repo):
            errors = _run(_orchestrator(), found)
        error = errors[0]
        assert error["code"] == "clone_failed"
        assert (error["step"], error["git_exit_code"], error["cause"]) == ("clone", 128, "repo_not_found")
        assert LEAK not in str(error)

    def test_a_branch_failure_is_told_from_a_clone_failure(self):
        class _Repo:
            def __init__(self, **_k):
                self.repo = "acme/app"

            def clone(self):
                return "/tmp/x"

            def create_branch(self, _name):
                raise GitCommandError("Branch create failed: fatal", 128, "")

        async def found(_rid):
            return {"projectId": "p1", "title": "t"}

        with mock.patch.object(module, "GitHubRepoManager", _Repo):
            errors = _run(_orchestrator(), found)
        assert errors[0]["step"] == "create_branch"
        assert "cause" not in errors[0]

    @pytest.mark.parametrize("stderr,cause", [
        ("fatal: Authentication failed for 'https://github.com/a/b.git/'", "auth_failed"),
        ("remote: Repository not found.", "repo_not_found"),
        ("fatal: Remote branch dev not found in upstream origin", "branch_not_found"),
        ("fatal: unable to access: Could not resolve host: github.com", "network_error"),
        ("something new", ""),
    ])
    def test_git_stderr_is_reduced_to_a_fixed_cause(self, stderr, cause):
        assert git_failure_cause(stderr) == cause


class TestThePullRequestAndTheModel:
    def test_a_github_refusal_carries_its_status_and_short_title(self):
        class GithubException(Exception):
            status = 403
            data = {"message": "Resource not accessible by integration",
                    "documentation_url": "https://docs.github.com/x"}

        details = module._git_details(GithubException())
        assert details == {"github_status": 403,
                           "github_message": "Resource not accessible by integration"}

    def test_a_github_message_that_is_not_a_short_title_is_dropped(self):
        class GithubException(Exception):
            status = 422
            data = {"message": f"A pull request already exists for acme:{LEAK}"}

        assert module._git_details(GithubException()) == {"github_status": 422}

    def test_a_failed_model_call_carries_the_provider_status(self):
        class RateLimitError(Exception):
            status_code = 429

        callback = _Callback()
        orch = _orchestrator(callback)
        orch.state.settings = module.CodeFixSettings(model="gpt-5", github_repo="acme/app")

        async def failing_call(*_a, **_k):
            raise RateLimitError(f"quota {LEAK}")

        async def no_sleep(_s):
            return None

        orch._call_llm = failing_call
        orch.state.settings.max_iterations = 3
        # Drive just the ReAct loop's failure branch through the real code.
        with mock.patch.object(module.asyncio, "sleep", no_sleep):
            asyncio.run(_drive_loop(orch))
        error = callback.errors[-1]
        assert error["code"] == "llm_error"
        assert (error["provider_status"], error["error_class"]) == (429, "RateLimitError")
        assert LEAK not in str(error)


def test_a_rate_limited_model_call_is_waited_out():
    from langchain_core.messages import AIMessage

    class RateLimitError(Exception):
        status_code = 429

    class Model:
        calls = 0

        def bind_tools(self, _tools):
            return self

        async def ainvoke(self, _messages):
            Model.calls += 1
            if Model.calls == 1:
                raise RateLimitError("Rate limit reached. Please try again in 2s.")
            return AIMessage(content="done")

    orch = _orchestrator()
    orch.llm_client = Model()
    with mock.patch("orchestrator_helpers.llm_retry.asyncio.sleep", new=mock.AsyncMock()):
        result = asyncio.run(orch._call_llm("system", [{"role": "user", "content": "fix it"}]))
    assert result["content"] == [{"type": "text", "text": "done"}]
    assert Model.calls == 2


async def _drive_loop(orch):
    """Run `run()` past the clone with every outside call stubbed."""
    async def settings(_project_id):
        return dict(SETTINGS)

    async def found(_rid):
        return {"projectId": "p1", "title": "t"}

    async def nothing(*_a, **_k):
        return None

    async def listing(_state):
        return ""

    class _Repo:
        def __init__(self, **_k):
            self.repo = "acme/app"

        def clone(self):
            return "/tmp/x"

        def create_branch(self, _name):
            return None

        def cleanup(self):
            return None

    async def llm():
        return object()

    orch._load_remediation = found
    orch._update_remediation = nothing
    orch._init_llm = llm
    orch._finalize = nothing
    with mock.patch.object(module, "load_cypherfix_settings", settings), \
         mock.patch.object(module, "GitHubRepoManager", _Repo), \
         mock.patch.object(module.sandbox_client, "spawn", nothing), \
         mock.patch.object(module, "github_list_dir", listing), \
         mock.patch.object(module, "build_codefix_system_prompt", lambda *a: "prompt"):
        await orch.run("rem-1")
