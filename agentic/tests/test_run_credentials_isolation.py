"""RBAC HD-16 / NF-07 (F-16): a run spends only its own owner's credentials.

Two concurrent runs of different owners on the same model id each get the client
built with their owner's key (the single `orchestrator.llm` slot is gone: clients
are cached by model id, provider fingerprint and owner), every search tool reads
the key of the run it serves at call time, an empty key means none (never the
previous run's), and the GitHub token of the tradecraft tool is per run too. The
out-of-run routes (/guardrail/check-target, /tradecraft/verify) build their own
per-user client.
"""
import asyncio
import contextvars
import os
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

os.environ.setdefault("WEBAPP_API_URL", "http://fake-webapp")

import project_settings as ps
import agent_context as ac
from orchestrator_helpers import llm_setup

MODEL = "gpt-4o-mini"


class _Client:
    """A model client that remembers the key it was built with and every prompt."""

    def __init__(self, model, key):
        self.model, self.key, self.prompts = model, key, []

    async def ainvoke(self, prompt, *_a, **_k):
        self.prompts.append(prompt)
        return SimpleNamespace(content="MATCH (n:Domain) RETURN n LIMIT 1")


def _fake_setup_llm(model, **kw):
    key = kw.get("openai_api_key")
    if not key:
        raise ValueError(f"OpenAI API key is required for model '{model}'")
    return _Client(model, key)


def _owner_settings(owner, key=None, *, model=MODEL, **user_settings):
    providers = [{"id": f"prov-{owner}", "userId": owner, "providerType": "openai", "apiKey": key}] if key else []
    return {**ps.DEFAULT_AGENT_SETTINGS, "OPENAI_MODEL": model,
            "USER_LLM_PROVIDERS": providers, "USER_SETTINGS": dict(user_settings)}


def _orchestrator():
    from orchestrator import AgentOrchestrator
    orch = AgentOrchestrator.__new__(AgentOrchestrator)
    orch.neo4j_manager = SimpleNamespace(llm=None)
    return orch


class _Reset(unittest.TestCase):
    def setUp(self):
        self._orig_fetch = ps.fetch_agent_settings
        self.projects = {}
        ps.fetch_agent_settings = lambda pid, _url: dict(self.projects[pid])
        patcher = mock.patch.object(llm_setup, "setup_llm", side_effect=_fake_setup_llm)
        self.setup_llm = patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        ps.fetch_agent_settings = self._orig_fetch
        ps._settings = None
        ps._settings_ctx.set(None)
        ac.current_llm.set(None)


class ModelClientPerRun(_Reset):
    def test_two_concurrent_runs_same_model_different_owners_each_call_uses_its_owners_client(self):
        self.projects = {"PA": _owner_settings("owner-a", "sk-A"), "PB": _owner_settings("owner-b", "sk-B")}
        orch = _orchestrator()
        seen = {}

        async def run(pid, barrier):
            llm_setup.apply_project_settings(orch, pid)
            await barrier.wait()            # both applied: the old shared slot held the last one
            client = orch.llm               # what every graph node reads
            await client.ainvoke(f"think of {pid}")
            seen[pid] = client

        async def main():
            barrier = asyncio.Barrier(2)
            await asyncio.gather(run("PA", barrier), run("PB", barrier))

        asyncio.run(main())
        self.assertEqual((seen["PA"].key, seen["PB"].key), ("sk-A", "sk-B"))
        self.assertEqual(seen["PA"].prompts, ["think of PA"])
        self.assertEqual(seen["PB"].prompts, ["think of PB"])
        self.assertEqual(self.setup_llm.call_count, 2)
        # Text-to-cypher reads the run's client; no apply writes a shared manager slot.
        self.assertIsNone(orch.neo4j_manager.llm)

    def test_text_to_cypher_runs_on_the_runs_own_client(self):
        from tools import Neo4jToolManager
        self.projects = {"PA": _owner_settings("owner-a", "sk-A"), "PB": _owner_settings("owner-b", "sk-B")}
        orch = _orchestrator()
        manager = Neo4jToolManager("bolt://x", "u", "p", llm=None)
        seen = {}

        async def fake_retry(llm, prompt, **_k):
            return await llm.ainvoke(prompt)

        async def run(pid, barrier):
            llm_setup.apply_project_settings(orch, pid)
            await barrier.wait()
            await manager._generate_cypher(f"domains of {pid}")
            seen[pid] = ac.current_llm.get()

        async def main():
            barrier = asyncio.Barrier(2)
            await asyncio.gather(run("PA", barrier), run("PB", barrier))

        with mock.patch("orchestrator_helpers.llm_retry.retry_llm_call", fake_retry):
            asyncio.run(main())
        self.assertIn("domains of PA", seen["PA"].prompts[0])
        self.assertIn("domains of PB", seen["PB"].prompts[0])
        self.assertEqual((seen["PA"].key, seen["PB"].key), ("sk-A", "sk-B"))

    def test_a_run_whose_owner_has_no_provider_gets_no_client_not_the_previous_runs(self):
        self.projects = {"PA": _owner_settings("owner-a", "sk-A"), "PB": _owner_settings("owner-b")}
        orch = _orchestrator()
        llm_setup.apply_project_settings(orch, "PA")
        self.assertEqual(orch.llm.key, "sk-A")
        llm_setup.apply_project_settings(orch, "PB")
        self.assertIsNone(orch.llm)
        self.assertIsNone(ac.current_llm.get())
        self.assertEqual(orch.llm_setup_failure["code"], "llm_not_configured")

    def test_a_task_that_never_loaded_a_project_reads_no_client(self):
        self.projects = {"PA": _owner_settings("owner-a", "sk-A")}
        orch = _orchestrator()
        fresh = contextvars.copy_context()
        llm_setup.apply_project_settings(orch, "PA")
        self.assertEqual(orch.llm.key, "sk-A")
        self.assertIsNone(fresh.run(lambda: orch.llm))

    def test_the_same_owner_and_credential_reuse_one_client(self):
        self.projects = {"PA": _owner_settings("owner-a", "sk-A"), "PA2": _owner_settings("owner-a", "sk-A")}
        orch = _orchestrator()
        llm_setup.apply_project_settings(orch, "PA")
        first = orch.llm
        llm_setup.apply_project_settings(orch, "PA2")
        self.assertIs(orch.llm, first)
        self.assertEqual(self.setup_llm.call_count, 1)

    def test_a_changed_key_builds_a_new_client(self):
        self.projects = {"PA": _owner_settings("owner-a", "sk-A")}
        orch = _orchestrator()
        llm_setup.apply_project_settings(orch, "PA")
        self.projects["PA"] = _owner_settings("owner-a", "sk-A-rotated")
        llm_setup.apply_project_settings(orch, "PA")
        self.assertEqual(orch.llm.key, "sk-A-rotated")
        self.assertEqual(self.setup_llm.call_count, 2)

    def test_the_cache_is_bounded(self):
        orch = _orchestrator()
        limit = llm_setup.LlmClientCache.MAX_ENTRIES
        for i in range(limit + 5):
            self.projects[f"P{i}"] = _owner_settings(f"owner-{i}", f"sk-{i}")
            llm_setup.apply_project_settings(orch, f"P{i}")
        self.assertEqual(len(orch._llm_cache), limit)

    def test_the_cache_key_holds_no_credential(self):
        orch = _orchestrator()
        self.projects = {"PA": _owner_settings("owner-a", "sk-very-secret")}
        llm_setup.apply_project_settings(orch, "PA")
        self.assertNotIn("sk-very-secret", repr(orch._llm_cache.keys()))


def _run_settings(**user_settings):
    """Bind a run's settings to the current task, as load_project_settings does."""
    ps._settings_ctx.set({**ps.DEFAULT_AGENT_SETTINGS, "USER_SETTINGS": user_settings})


class _Http:
    """httpx.AsyncClient stand-in recording the SerpAPI key of each request."""
    keys = []

    def __init__(self, *_a, **_k):
        pass

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_a):
        return False

    async def get(self, _url, params=None, **_k):
        _Http.keys.append(params["api_key"])
        return SimpleNamespace(raise_for_status=lambda: None, json=lambda: {"organic_results": []})


class _Tavily:
    keys = []

    def __init__(self, **kw):
        _Tavily.keys.append(kw["tavily_api_key"])

    async def ainvoke(self, _args):
        return []


class SearchKeysPerRun(unittest.TestCase):
    def setUp(self):
        _Http.keys, _Tavily.keys = [], []
        self.addCleanup(ps._settings_ctx.set, None)
        for target, value in (("tools.httpx.AsyncClient", _Http), ("langchain_tavily.TavilySearch", _Tavily)):
            patcher = mock.patch(target, value)
            patcher.start()
            self.addCleanup(patcher.stop)
        self.host = mock.AsyncMock(side_effect=lambda key, ip: f"host {ip} via {key}")
        patcher = mock.patch("tools._action_host", self.host)
        patcher.start()
        self.addCleanup(patcher.stop)

    def _tools(self):
        from tools import GoogleDorkToolManager, ShodanToolManager, WebSearchToolManager
        tools = {
            "shodan": ShodanToolManager(keys_from_run=True).get_tool(),
            "google_dork": GoogleDorkToolManager(keys_from_run=True).get_tool(),
            "web_search": WebSearchToolManager(keys_from_run=True).get_tool(),
        }
        for name, t in tools.items():
            self.assertIsNotNone(t, f"{name} must exist with no key at start: keys come per run")
        return tools

    async def _use_all(self, tools):
        return {
            "shodan": await tools["shodan"].ainvoke({"action": "host", "ip": "192.0.2.1"}),
            "google_dork": await tools["google_dork"].ainvoke({"query": "site:example.com"}),
            "web_search": await tools["web_search"].ainvoke({"query": "CVE-2024-0001"}),
        }

    def test_each_tool_sees_its_own_tavily_shodan_serpapi_key(self):
        tools = self._tools()
        out = {}

        async def run(owner, barrier):
            _run_settings(tavilyApiKey=f"tvly-{owner}", shodanApiKey=f"shodan-{owner}",
                          serpApiKey=f"serp-{owner}")
            await barrier.wait()
            out[owner] = await self._use_all(tools)

        async def main():
            barrier = asyncio.Barrier(2)
            await asyncio.gather(run("A", barrier), run("B", barrier))

        asyncio.run(main())
        self.assertEqual(out["A"]["shodan"], "host 192.0.2.1 via shodan-A")
        self.assertEqual(out["B"]["shodan"], "host 192.0.2.1 via shodan-B")
        self.assertEqual(sorted(_Http.keys), ["serp-A", "serp-B"])
        self.assertEqual(sorted(_Tavily.keys), ["tvly-A", "tvly-B"])

    def test_an_empty_key_does_not_inherit_the_previous_runs(self):
        tools = self._tools()

        async def owner_a():
            _run_settings(tavilyApiKey="tvly-A", shodanApiKey="shodan-A", serpApiKey="serp-A")
            return await self._use_all(tools)

        async def owner_b():
            _run_settings()
            return await self._use_all(tools)

        async def main():
            await asyncio.create_task(owner_a())
            return await asyncio.create_task(owner_b())

        out_b = asyncio.run(main())
        self.assertEqual(_Http.keys, ["serp-A"])
        self.assertEqual(_Tavily.keys, ["tvly-A"])
        self.assertEqual(self.host.await_count, 1)
        self.assertIn("not configured", out_b["shodan"])
        self.assertIn("not configured", out_b["google_dork"])
        self.assertIn("Tavily is not configured", out_b["web_search"])

    def test_outside_a_run_the_last_loaded_projects_keys_are_never_used(self):
        tools = self._tools()
        # The module-global settings are the last loader's: another owner's keys.
        ps._settings = {**ps.DEFAULT_AGENT_SETTINGS, "USER_SETTINGS": {"shodanApiKey": "shodan-other"}}
        self.addCleanup(setattr, ps, "_settings", None)
        ps._settings_ctx.set(None)
        out = asyncio.run(tools["shodan"].ainvoke({"action": "host", "ip": "192.0.2.1"}))
        self.assertIn("not configured", out)
        self.host.assert_not_awaited()

    def test_rotation_stays_inside_each_owners_own_pool(self):
        tools = self._tools()
        seen = {"A": [], "B": []}

        def pool(owner):
            return {"shodanApiKey": f"{owner}1", "rotationConfigs": {
                "shodan": {"extraKeys": [f"{owner}2"], "rotateEveryN": 1}}}

        async def run(owner, turns):
            _run_settings(**pool(owner))
            for _ in range(3):
                await turns[owner].wait()
                turns[owner].clear()
                seen[owner].append(await tools["shodan"].ainvoke({"action": "host", "ip": "192.0.2.1"}))
                turns["B" if owner == "A" else "A"].set()

        async def main():
            turns = {"A": asyncio.Event(), "B": asyncio.Event()}
            turns["A"].set()
            await asyncio.gather(run("A", turns), run("B", turns))

        asyncio.run(main())
        self.assertEqual([s.rsplit(" ", 1)[1] for s in seen["A"]], ["A1", "A2", "A1"])
        self.assertEqual([s.rsplit(" ", 1)[1] for s in seen["B"]], ["B1", "B2", "B1"])

    def test_the_orchestrator_writes_no_key_onto_a_shared_manager(self):
        from tools import GoogleDorkToolManager, ShodanToolManager, WebSearchToolManager
        orch = _orchestrator()
        orch._web_search_manager = WebSearchToolManager(keys_from_run=True)
        orch._shodan_manager = ShodanToolManager(keys_from_run=True)
        orch._google_dork_manager = GoogleDorkToolManager(keys_from_run=True)
        orch._tradecraft_manager = None
        orch.tool_executor = None
        settings = _owner_settings("owner-a", "sk-A", tavilyApiKey="tvly-A", shodanApiKey="shodan-A",
                                   serpApiKey="serp-A", githubAccessToken="ghp-A")
        with mock.patch.object(llm_setup, "load_project_settings", return_value=settings), \
                mock.patch.object(llm_setup, "setup_llm", side_effect=_fake_setup_llm):
            orch._apply_project_settings("PA")
        for manager in (orch._web_search_manager, orch._shodan_manager, orch._google_dork_manager):
            self.assertEqual((manager.api_key, manager.key_rotator), ("", None))
        self.assertFalse(hasattr(orch, "_user_settings"))


class GitHubTokenPerRun(unittest.TestCase):
    def test_github_token_per_run(self):
        from orchestrator_helpers import tradecraft_lookup as tl
        manager = tl.TradecraftLookupManager(cache_root=tempfile.mkdtemp(prefix="tc-run-token-"))
        resource = {"id": "r1", "slug": "pocs", "name": "PoCs", "url": "https://github.com/x/pocs",
                    "enabled": True, "resourceType": "cve-poc-db", "sitemap": {}}
        tokens = []

        async def fake_lookup(cve, sitemap, github_token=""):
            tokens.append(github_token)
            return "poc body", "https://github.com/x/pocs/blob/main/poc.py", None

        async def run(token, barrier):
            ps._settings_ctx.set({**ps.DEFAULT_AGENT_SETTINGS,
                                  "USER_SETTINGS": {"githubAccessToken": token} if token else {}})
            manager.set_resources([resource])
            await barrier.wait()
            await manager._invoke(resource_id="pocs", query="q", cve_id="CVE-2024-0001",
                                  section_path=None, force_refresh=True)

        async def main():
            barrier = asyncio.Barrier(3)
            await asyncio.gather(run("ghp-A", barrier), run("ghp-B", barrier), run("", barrier))

        self.addCleanup(ps._settings_ctx.set, None)
        with mock.patch.object(tl, "_cve_lookup_detailed", fake_lookup):
            asyncio.run(main())
        self.assertEqual(sorted(tokens), ["", "ghp-A", "ghp-B"])

    def test_a_resources_own_token_still_wins(self):
        from orchestrator_helpers import tradecraft_lookup as tl
        manager = tl.TradecraftLookupManager(cache_root=tempfile.mkdtemp(prefix="tc-run-token-"))
        resource = {"id": "r1", "slug": "pocs", "name": "PoCs", "url": "https://github.com/x/pocs",
                    "enabled": True, "resourceType": "cve-poc-db", "sitemap": {},
                    "githubTokenOverride": "ghp-resource"}
        tokens = []

        async def fake_lookup(cve, sitemap, github_token=""):
            tokens.append(github_token)
            return "poc body", "https://github.com/x/pocs/blob/main/poc.py", None

        async def run():
            ps._settings_ctx.set({**ps.DEFAULT_AGENT_SETTINGS, "USER_SETTINGS": {"githubAccessToken": "ghp-A"}})
            manager.set_resources([resource])
            await manager._invoke(resource_id="pocs", query="q", cve_id="CVE-2024-0001",
                                  section_path=None, force_refresh=True)

        self.addCleanup(ps._settings_ctx.set, None)
        with mock.patch.object(tl, "_cve_lookup_detailed", fake_lookup):
            asyncio.run(run())
        self.assertEqual(tokens, ["ghp-resource"])


class _Tag:
    def __init__(self, source):
        self.source = source


class OutOfRunRoutesBuildTheirOwnClient(unittest.TestCase):
    def setUp(self):
        import api
        self.api = api

    def test_guardrail_uses_the_named_users_client_never_the_last_runs(self):
        orch = mock.MagicMock(_initialized=True, llm=_Tag("another-owners-run"))
        used = []

        async def check(llm, **_k):
            used.append(llm.source)
            return {"allowed": True, "reason": "ok"}

        with mock.patch.object(self.api, "orchestrator", orch), \
                mock.patch.object(self.api, "_build_llm_for_user", side_effect=lambda uid: _Tag(f"user:{uid}")), \
                mock.patch("orchestrator_helpers.guardrail.check_target_allowed", check):
            out = asyncio.run(self.api.check_target_guardrail(
                self.api.GuardrailRequest(target_domain="example.com", user_id="owner-b", project_id="PB")))
        self.assertEqual(out, {"allowed": True, "reason": "ok"})
        self.assertEqual(used, ["user:owner-b"])
        orch._apply_project_settings.assert_not_called()
        self.assertEqual(orch.llm.source, "another-owners-run")

    def test_guardrail_without_a_buildable_model_is_skipped_open(self):
        orch = mock.MagicMock(_initialized=True, llm=_Tag("another-owners-run"))
        check = mock.AsyncMock()
        with mock.patch.object(self.api, "orchestrator", orch), \
                mock.patch.object(self.api, "_build_llm_for_user", side_effect=ValueError("no key")), \
                mock.patch("orchestrator_helpers.guardrail.check_target_allowed", check):
            out = asyncio.run(self.api.check_target_guardrail(
                self.api.GuardrailRequest(target_domain="example.com", user_id="owner-b")))
        self.assertEqual(out, {"allowed": True, "reason": "LLM not configured, guardrail skipped"})
        check.assert_not_awaited()

    def test_tradecraft_verify_without_a_model_builds_the_users_client(self):
        captured = {}

        async def fake_verify(url, *, github_token, force, llm, mcp_manager, bounds):
            captured["llm"] = llm.source
            return {"summary": "", "resource_type": "agentic-crawl", "sitemap": {},
                    "crawl_stopped_because": "", "crawl_stats": {}, "last_error": ""}

        orch = mock.MagicMock(_initialized=True, llm=_Tag("another-owners-run"), _mcp_manager=None)
        with mock.patch.object(self.api, "orchestrator", orch), \
                mock.patch("orchestrator_helpers.tradecraft_lookup.verify_resource", fake_verify), \
                mock.patch("orchestrator_helpers.tradecraft_lookup.validate_url", return_value=(True, "")), \
                mock.patch.object(self.api, "_build_llm_for_user", side_effect=lambda uid: _Tag(f"user:{uid}")):
            asyncio.run(self.api.tradecraft_verify(self.api.TradecraftVerifyRequest(
                url="https://docs.example.test/", user_id="owner-b")))
        self.assertEqual(captured["llm"], "user:owner-b")


if __name__ == "__main__":
    unittest.main()
