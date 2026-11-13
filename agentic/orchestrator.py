"""
RedAmon Agent Orchestrator

ReAct-style agent orchestrator with iterative Thought-Tool-Output pattern.
Supports phase tracking, LLM-managed todo lists, and checkpoint-based approval.
"""

import asyncio
import os
import logging
from contextlib import asynccontextmanager
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from state import (
    NO_APPROVAL_ANSWER,
    NO_TOOL_CONFIRMATION_ANSWER,
    AgentState,
    InvokeResponse,
    summarize_trace_for_response,
)
from project_settings import get_setting
from mcp_toolset_guard import (
    MCP_TOOLSET_BUSY_RESUME_MESSAGE, McpToolsetBusy, server_set_hash, toolset_guard,
)
from tools import (
    MCPToolsManager,
    Neo4jToolManager,
    WebSearchToolManager,
    ShodanToolManager,
    GoogleDorkToolManager,
    PhaseAwareToolExecutor,
)
from orchestrator_helpers import (
    set_checkpointer,
    create_config,
    get_config_values,
)
from orchestrator_helpers.llm_setup import apply_project_settings
from agent_context import current_llm, current_llm_wait_listener
from agent_in_the_loop.broker import get_broker
from agent_in_the_loop import is_loop_llm
from prompt_safety import fence_node_context
from orchestrator_helpers.streaming import clear_stale_streaming_state, emit_streaming_events
from orchestrator_helpers.body_sweep import sweep_session_bodies
from orchestrator_helpers.nodes import (
    initialize_node,
    think_node,
    execute_tool_node,
    execute_plan_node,
    generate_response_node,
    await_approval_node,
    process_approval_node,
    await_question_node,
    process_answer_node,
    await_tool_confirmation_node,
    process_tool_confirmation_node,
    fireteam_deploy_node,
    fireteam_collect_node,
    process_fireteam_confirmation_node,
)
from orchestrator_helpers.fireteam_member_graph import build_fireteam_member_graph

# Default checkpointer. Replaced with AsyncPostgresSaver inside
# AgentOrchestrator.initialize() when PERSISTENT_CHECKPOINTER=true.
checkpointer = MemorySaver()
set_checkpointer(checkpointer)

logger = logging.getLogger(__name__)

NO_PENDING_REQUEST_MESSAGE = (
    "Nothing is waiting for this answer: the request was already answered, or a newer "
    "message replaced it. Your answer was not applied."
)

# A new message never approves or confirms anything. Set to None in its graph input, so an
# answer left in a checkpoint beside a request can never be applied by the next message
# (initialize resumes on "answer + request"), with no permission check and no audit row.
_NO_ANSWER = {**NO_APPROVAL_ANSWER, **NO_TOOL_CONFIRMATION_ANSWER}

# Base URL for session manager (kali-sandbox HTTP server on port 8013)
_SESSION_MANAGER_BASE = os.environ.get(
    "MCP_METASPLOIT_PROGRESS_URL", "http://kali-sandbox:8013/progress"
).rsplit("/progress", 1)[0]


class AgentOrchestrator:
    """
    ReAct-style agent orchestrator for penetration testing.

    Implements the Thought-Tool-Output pattern with:
    - Phase tracking (Informational → Exploitation → Post-Exploitation)
    - LLM-managed todo lists
    - Checkpoint-based approval for phase transitions
    - Full execution trace in memory
    """

    def __init__(self):
        """Initialize the orchestrator with configuration."""
        # Infrastructure-only env vars (stay in docker-compose)
        self.neo4j_uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.neo4j_user = os.getenv("NEO4J_USER", "neo4j")
        self.neo4j_password = os.getenv("NEO4J_PASSWORD")

        self.tool_executor: Optional[PhaseAwareToolExecutor] = None
        self.neo4j_manager: Optional[Neo4jToolManager] = None
        self.graph = None

        self._initialized = False
        # Per-session maps — keyed by session_id so concurrent sessions
        # don't overwrite each other's callback / guidance queue.
        self._streaming_callbacks: dict[str, object] = {}
        self._guidance_queues: dict[str, asyncio.Queue] = {}
        self._graph_view_cyphers: dict[str, str | None] = {}

    async def initialize(self) -> None:
        """Initialize tools and graph (LLM setup deferred until project_id is known)."""
        if self._initialized:
            logger.warning("Orchestrator already initialized")
            return

        logger.info("Initializing AgentOrchestrator...")

        await self._setup_tools()
        await self._setup_checkpointer()
        self._build_graph()
        await self.recover_orphaned_fireteams()
        self._initialized = True

        logger.info("AgentOrchestrator initialized (LLM deferred until project settings loaded)")

    @property
    def llm(self) -> Optional[BaseChatModel]:
        """This run's model client, or None outside a run (RBAC T17).

        There is no shared slot: `apply_project_settings` binds each run's own
        client (llm_setup.LlmClientCache) to its task through `current_llm`, which
        the graph's nodes and Fireteam members inherit. A task that never loaded a
        project reads None, never the client of whichever run loaded last.
        """
        return current_llm.get()

    @llm.setter
    def llm(self, value: Optional[BaseChatModel]) -> None:
        current_llm.set(value)

    async def recover_orphaned_fireteams(self) -> None:
        """Mark fireteams from a prior process (still 'running') as cancelled.

        Called once from the FastAPI lifespan after checkpointer setup. Uses
        the Postgres pool directly to avoid round-tripping through the webapp
        API for a startup-only maintenance task.
        """
        if not self._checkpoint_pool:
            return
        try:
            async with self._checkpoint_pool.connection() as conn:
                # Mark running members as cancelled if their fireteam is stale (>60s old).
                await conn.execute(
                    """
                    UPDATE fireteam_members
                    SET status = 'cancelled',
                        completion_reason = 'backend_restart',
                        completed_at = NOW()
                    WHERE status = 'running'
                      AND fireteam_id IN (
                          SELECT id FROM fireteams
                          WHERE status IN ('pending', 'running')
                            AND started_at < NOW() - INTERVAL '60 seconds'
                      )
                    """
                )
                await conn.execute(
                    """
                    UPDATE fireteams
                    SET status = 'cancelled',
                        completed_at = NOW()
                    WHERE status IN ('pending', 'running')
                      AND started_at < NOW() - INTERVAL '60 seconds'
                    """
                )
            logger.info("recover_orphaned_fireteams: stale fireteams and members marked cancelled")
        except Exception as exc:
            logger.warning("recover_orphaned_fireteams failed: %s", exc)

    async def _setup_checkpointer(self) -> None:
        """Optionally replace MemorySaver with AsyncPostgresSaver.

        Driven by the PERSISTENT_CHECKPOINTER setting. Failure to connect
        is logged and falls back to MemorySaver so the app still starts.
        """
        global checkpointer
        if not get_setting("PERSISTENT_CHECKPOINTER", False):
            logger.info("PERSISTENT_CHECKPOINTER=false; using MemorySaver (non-persistent)")
            self._checkpoint_pool = None
            return
        try:
            from langgraph.checkpoint.postgres.aio import AsyncPostgresSaver
            from psycopg_pool import AsyncConnectionPool

            dsn = os.environ.get("DATABASE_URL")
            if not dsn:
                logger.warning("PERSISTENT_CHECKPOINTER=true but DATABASE_URL missing; falling back to MemorySaver")
                self._checkpoint_pool = None
                return

            pool = AsyncConnectionPool(
                conninfo=dsn,
                max_size=get_setting("CHECKPOINT_POOL_MAX_SIZE", 20),
                kwargs={"autocommit": True, "prepare_threshold": 0},
                open=False,
            )
            await pool.open()
            pg_cp = AsyncPostgresSaver(pool)
            await pg_cp.setup()
            # Swap global and re-register with orchestrator_helpers.config.
            checkpointer = pg_cp
            set_checkpointer(pg_cp)
            self._checkpoint_pool = pool
            logger.info("Using AsyncPostgresSaver for persistent checkpointing")
        except Exception as exc:
            logger.warning("AsyncPostgresSaver setup failed (%s); falling back to MemorySaver", exc)
            self._checkpoint_pool = None

    # =========================================================================
    # METASPLOIT PREWARM
    # =========================================================================

    # =========================================================================
    # LLM & PROJECT SETTINGS
    # =========================================================================

    def _apply_project_settings(self, project_id: str) -> None:
        """Load project settings and bind this run's model client and tradecraft catalog.

        No credential is written onto a shared manager here (RBAC T17): the search
        tools, their rotation pools and the tradecraft GitHub token are read at call
        time from the run's own USER_SETTINGS (tools.run_user_settings), so an empty
        key means none, never the previous run's. The user MCP toolset is admitted at
        run start (_mcp_toolset_lease), under the guard of mcp_toolset_guard.
        """
        apply_project_settings(self, project_id)

        if self._tradecraft_manager and self.tool_executor:
            # The tradecraft tool stays permanently registered on the executor
            # (get_tool no longer swapped per turn, which raced). Per session we
            # only bind this project's resources + prompt catalog; a disabled
            # project clears its own resources so the always-registered tool
            # returns "resource not configured".
            if get_setting('TRADECRAFT_TOOL_ENABLED', True):
                self._tradecraft_manager.set_resources(get_setting('TRADECRAFT_RESOURCES', []) or [])
                self._tradecraft_manager.section_picker_llm = self._build_section_picker_llm()
                # tier2_threshold_bytes / fetch_timeout / default_ttl are read per
                # session at use-time from the task-isolated TRADECRAFT_* settings.
                # Swap this session's per-resource catalog into the prompt (overlay).
                from prompts.tool_registry import swap_tradecraft_entry
                swap_tradecraft_entry(self._tradecraft_manager.build_registry_entry())
                logger.info(
                    f"Tradecraft Lookup: {len(self._tradecraft_manager._resources)} resources"
                )
            else:
                self._tradecraft_manager.set_resources([])
                from prompts.tool_registry import pop_tradecraft_entry
                pop_tradecraft_entry()

    def _build_section_picker_llm(self):
        """This session's "Tradecraft section picker" LLM, or None.

        Read from the task-isolated USER_SETTINGS / USER_LLM_PROVIDERS, never
        another run's. None means no model is set or it cannot be built, and the
        picker then chooses the page by text match.
        """
        from feature_models import feature_model
        user_settings = get_setting('USER_SETTINGS', {}) or {}
        model = feature_model(user_settings, 'tradecraft_section_picker')
        if not model:
            return None
        try:
            from llm_builder import build_llm_from_providers
            providers = get_setting('USER_LLM_PROVIDERS', []) or []
            return build_llm_from_providers(model, providers)
        except Exception as e:                                    # noqa: BLE001
            logger.warning(
                f"Section picker model {model} could not be built "
                f"({e.__class__.__name__}); pages are picked by text match")
            return None

    # =========================================================================
    # TOOLS & GRAPH SETUP
    # =========================================================================

    async def _setup_tools(self) -> None:
        """Set up all tools (MCP and Neo4j)."""
        # Build MCP server config: 5 system servers + (later, after project
        # settings load) any user-managed servers from UserSettings.mcpServers.
        # User servers are merged in via reload_mcp_manifests() once the
        # project's settings are available; at startup we only have the
        # system set so the agent can come up cleanly.
        from tools import _build_system_mcp_servers
        import mcp_registry
        system_servers = _build_system_mcp_servers()
        mcp_registry.set_current(system_servers)
        server_configs, env_warnings = mcp_registry.to_mcp_servers_dict(system_servers)
        if env_warnings:
            mcp_registry.set_current(system_servers, warnings=env_warnings)

        mcp_manager = MCPToolsManager(server_configs=server_configs)
        mcp_tools = await mcp_manager.get_tools()

        # No client of its own: text-to-Cypher runs on the calling run's client
        # (current_llm), so it is never another owner's.
        self.neo4j_manager = Neo4jToolManager(
            uri=self.neo4j_uri,
            user=self.neo4j_user,
            password=self.neo4j_password,
            llm=None,
        )
        graph_tool = self.neo4j_manager.get_tool()
        # The two companions ride on the SAME condition as query_graph:
        # get_tool() returns None when Neo4j setup fails, and a companion that
        # was offered anyway would fail on every call instead of disappearing.
        graph_schema_tool = self.neo4j_manager.get_schema_tool() if graph_tool else None
        graph_summary_tool = self.neo4j_manager.get_summary_tool() if graph_tool else None

        # Setup Knowledge Base (FAISS + Neo4j hybrid)
        self._knowledge_base = self._setup_knowledge_base()

        # If KB is not available, swap the web_search tool registry entry
        # to a simplified Tavily-only description so the LLM doesn't use
        # KB-specific parameters (include_sources, exclude_sources, min_cvss)
        if self._knowledge_base is None:
            from prompts.tool_registry import TOOL_REGISTRY, WEB_SEARCH_TAVILY_ONLY
            TOOL_REGISTRY["web_search"] = WEB_SEARCH_TAVILY_ONLY

        # The search tools are always registered and read each run's own key at
        # call time: a run without a key gets "not configured".
        # KB is passed in so web_search can check it before falling back to Tavily
        self._web_search_manager = WebSearchToolManager(knowledge_base=self._knowledge_base)
        web_search_tool = self._web_search_manager.get_tool()
        self._shodan_manager = ShodanToolManager()
        shodan_tool = self._shodan_manager.get_tool()
        self._google_dork_manager = GoogleDorkToolManager()
        google_dork_tool = self._google_dork_manager.get_tool()

        # Setup Tradecraft Lookup tool (resources resolved later via _apply_project_settings).
        # get_tool() returns None until at least one enabled resource is loaded.
        from orchestrator_helpers.tradecraft_lookup import TradecraftLookupManager
        self._tradecraft_manager = TradecraftLookupManager(mcp_manager=mcp_manager)
        # Tool starts as None; orchestrator hot-swaps it once resources load.
        tradecraft_tool = self._tradecraft_manager.get_tool()
        # Strip the registry entry until resources are loaded so the
        # baseline empty entry doesn't reach the system prompt.
        from prompts.tool_registry import pop_tradecraft_entry
        pop_tradecraft_entry()

        # Stash the MCP manager so the /tradecraft/verify HTTP endpoint can reach it.
        self._mcp_manager = mcp_manager

        # Create phase-aware tool executor
        self.tool_executor = PhaseAwareToolExecutor(
            mcp_manager, graph_tool, web_search_tool,
            shodan_tool, google_dork_tool,
            tradecraft_tool,
            graph_schema_tool=graph_schema_tool,
            graph_summary_tool=graph_summary_tool,
        )
        # No declared_tool_names filter at startup — only system MCP tools
        # are loaded. User MCPs (with their declared filter) come through
        # reload_mcp_manifests() once project settings are available.
        self.tool_executor.register_mcp_tools(mcp_tools)

        logger.info(f"Tools initialized: {len(self.tool_executor.get_all_tools())} available")

    async def reload_mcp_manifests(self, user_servers_raw=None, owner_id=None) -> dict:
        """Re-merge system + user MCP servers, refresh registry, reconnect MCP client.

        Called by the webapp's POST /mcp/reload after a user adds/edits/deletes an
        MCP server, once mcp_toolset_guard admitted it. Always reloads, even the set
        already loaded. A run loads its owner's set through _ensure_mcp_toolset.

        Args:
            user_servers_raw: list of dicts from UserSettings.mcpServers. None
                reloads the set already loaded, never the last-loaded project's
                settings (another owner's, possibly).
            owner_id: whose set it is (None: an administrator's reload).

        Raises McpToolsetBusy when, by the time its turn comes, another owner's run
        on a different set is live.

        Returns:
            dict with the new manifest snapshot (servers, errors, warnings,
            declared_tool_names) — same shape as GET /mcp/manifest body — and
            `loaded`, False when the set could not be loaded.
        """
        return await self._load_mcp_toolset(user_servers_raw, owner_id, force=True)

    async def _ensure_mcp_toolset(self, servers: list, owner_id) -> None:
        """Load the run's owner's set unless it is the loaded one. Awaited before the
        run streams, so its first tool call reaches its own owner's servers."""
        await self._load_mcp_toolset(servers, owner_id, force=False)

    async def _load_mcp_toolset(self, user_servers_raw, owner_id, *, force: bool):
        """One load at a time, in the order asked. The guard is asked again under the
        lock, because a run admitted while this load waited is live on its own set.
        A set is recorded as loaded only once it loaded."""
        guard = toolset_guard()
        async with self.__dict__.setdefault("_mcp_reload_lock", asyncio.Lock()):
            if user_servers_raw is None:
                user_servers_raw = guard.loaded_servers or []
            if not force and guard.loaded_hash == server_set_hash(user_servers_raw):
                return None
            if not guard.admit_reload(owner_id, user_servers_raw, via="reload" if force else "run"):
                raise McpToolsetBusy()
            try:
                result, loaded = await self._load_user_mcp_servers(user_servers_raw)
            except BaseException:
                # Cut short (a stopped run, a crash): the client may already hold the
                # new configs, so the previous record no longer describes it.
                guard.clear_loaded()
                raise
            if loaded:
                guard.record_loaded(user_servers_raw, owner_id)
            else:
                guard.clear_loaded()
            return {**result, "loaded": loaded}

    async def _load_user_mcp_servers(self, user_servers_raw: list) -> tuple:
        """Load system + user servers. Returns (manifest snapshot, loaded).

        A load that fails keeps no user MCP tool: the client answers all-or-nothing,
        and keeping the previous tools would route a call to the previous owner's
        server (and token) under a name this set declared. The system servers are
        loaded alone instead, so the Kali tools stay.
        """
        from tools import _build_system_mcp_servers
        from prompts.tool_registry import apply_mcp_manifests_to_registry
        import mcp_registry

        user_servers, parse_errors = mcp_registry.parse_user_servers(user_servers_raw)
        system_servers = _build_system_mcp_servers()
        all_servers = system_servers + user_servers

        server_configs, env_warnings = mcp_registry.to_mcp_servers_dict(all_servers)
        mcp_registry.set_current(all_servers, errors=parse_errors, warnings=env_warnings)

        declared_user_tools = apply_mcp_manifests_to_registry(user_servers)
        loaded = True

        # Swap the manager's config and force a reconnect to bind a fresh
        # MultiServerMCPClient that includes any new user-MCP URLs. Forced: a
        # transport-error rebuild that finished meanwhile used the previous configs.
        if hasattr(self, '_mcp_manager') and self._mcp_manager is not None:
            self._mcp_manager.replace_server_configs(server_configs)
            new_gen, new_tools = await self._mcp_manager.reconnect(
                self._mcp_manager.generation, reason="mcp_manifest_reload", force=True,
            )
            if new_tools:
                self.tool_executor.register_mcp_tools(
                    new_tools,
                    declared_tool_names=declared_user_tools,
                )
                logger.info(
                    f"MCP manifest reload: {len(user_servers)} user server(s), "
                    f"{len(declared_user_tools)} declared tool(s), "
                    f"{len(new_tools)} live tool(s) registered."
                )
            else:
                loaded = False
                system_tools = []
                if user_servers:
                    system_configs, _ = mcp_registry.to_mcp_servers_dict(system_servers)
                    self._mcp_manager.replace_server_configs(system_configs)
                    _, system_tools = await self._mcp_manager.reconnect(
                        self._mcp_manager.generation, reason="mcp_manifest_reload_system_only",
                        force=True,
                    )
                self.tool_executor.register_mcp_tools(system_tools or [], declared_tool_names=set())
                # A disabled server was never part of this load, so it is not a failed one.
                tried = sum(1 for s in user_servers if s.enabled)
                logger.warning(
                    f"MCP manifest reload failed: {tried} user server(s) not loaded; "
                    f"no user MCP tool is registered, {len(system_tools or [])} system tool(s). "
                    "The next run loads the set again."
                )

        return {
            "servers": mcp_registry.redact_for_api(all_servers),
            "errors": [e.model_dump() for e in parse_errors],
            "warnings": [w.model_dump() for w in env_warnings],
            "declared_user_tool_names": sorted(declared_user_tools),
        }, loaded

    def _setup_knowledge_base(self):
        """
        Initialize the Knowledge Base (FAISS + Neo4j) if enabled.

        Returns:
            PentestKnowledgeBase instance, or None if disabled or fails to load.
        """
        if os.getenv('KB_ENABLED', 'true').lower() != 'true':
            logger.info("KB_ENABLED=false — skipping knowledge base setup")
            return None

        try:
            from knowledge_base import PentestKnowledgeBase
            from knowledge_base.faiss_indexer import FAISSIndexer
            from knowledge_base.neo4j_loader import Neo4jLoader
            from knowledge_base.embedder import create_embedder
            from neo4j import GraphDatabase
        except ImportError as e:
            logger.warning(f"Knowledge base dependencies missing: {e} — KB disabled")
            return None

        try:
            kb_path = os.getenv('KB_PATH', '/app/knowledge_base/data')
            model_name = os.getenv('KB_EMBEDDING_MODEL', 'intfloat/e5-large-v2')

            embedder = create_embedder(model_name=model_name)
            faiss_indexer = FAISSIndexer(
                index_path=kb_path,
                dimensions=embedder.dimensions,
            )

            # Create a dedicated Neo4j driver for KB queries (separate from langchain wrapper)
            neo4j_driver = GraphDatabase.driver(
                self.neo4j_uri,
                auth=(self.neo4j_user, self.neo4j_password),
            )
            neo4j_loader = Neo4jLoader(neo4j_driver)

            kb = PentestKnowledgeBase(faiss_indexer, neo4j_loader, embedder)
            kb.load()

            stats = kb.stats()
            logger.info(f"Knowledge base loaded: {stats}")
            return kb
        except Exception as e:
            logger.warning(f"Failed to initialize knowledge base ({e}) — KB disabled, agent will fall back to Tavily")
            return None

    def _build_graph(self) -> None:
        """Build the ReAct LangGraph with phase tracking."""
        logger.info("Building ReAct LangGraph...")

        neo4j_creds = (self.neo4j_uri, self.neo4j_user, self.neo4j_password)
        builder = StateGraph(AgentState)

        # Add nodes — async wrappers that pass instance state to extracted functions
        async def _initialize(state, config=None):
            return await initialize_node(state, config, llm=self.llm, neo4j_creds=neo4j_creds)

        async def _think(state, config=None):
            return await think_node(state, config, llm=self.llm, guidance_queues=self._guidance_queues, neo4j_creds=neo4j_creds, streaming_callbacks=self._streaming_callbacks, graph_view_cyphers=self._graph_view_cyphers)

        async def _execute_tool(state, config=None):
            return await execute_tool_node(state, config, tool_executor=self.tool_executor, streaming_callbacks=self._streaming_callbacks, session_manager_base=_SESSION_MANAGER_BASE, graph_view_cyphers=self._graph_view_cyphers)

        async def _execute_plan(state, config=None):
            return await execute_plan_node(state, config, tool_executor=self.tool_executor, streaming_callbacks=self._streaming_callbacks, session_manager_base=_SESSION_MANAGER_BASE, graph_view_cyphers=self._graph_view_cyphers)

        async def _await_approval(state, config=None):
            await sweep_session_bodies(self.tool_executor, state)
            return await await_approval_node(state, config)

        async def _process_approval(state, config=None):
            return await process_approval_node(state, config, neo4j_creds=neo4j_creds)

        async def _await_question(state, config=None):
            return await await_question_node(state, config)

        async def _process_answer(state, config=None):
            return await process_answer_node(state, config)

        async def _generate_response(state, config=None):
            await sweep_session_bodies(self.tool_executor, state)
            return await generate_response_node(state, config, llm=self.llm, streaming_callbacks=self._streaming_callbacks, neo4j_creds=neo4j_creds)

        async def _await_tool_confirmation(state, config=None):
            return await await_tool_confirmation_node(state, config)

        async def _process_tool_confirmation(state, config=None):
            return await process_tool_confirmation_node(state, config)

        # --- Fireteam (multi-agent) ---
        # Prebuild the member graph once. Reads the member run's own client at
        # call time (self.llm is the task's current_llm).
        self.fireteam_member_graph = build_fireteam_member_graph(
            llm_getter=lambda: self.llm,
            tool_executor=self.tool_executor,
            streaming_callbacks=self._streaming_callbacks,
            session_manager_base=_SESSION_MANAGER_BASE,
            neo4j_creds=neo4j_creds,
            graph_view_cyphers=self._graph_view_cyphers,
        )

        async def _deploy_fireteam(state, config=None):
            return await fireteam_deploy_node(
                state, config,
                member_graph=self.fireteam_member_graph,
                streaming_callbacks=self._streaming_callbacks,
                neo4j_creds=neo4j_creds,
                graph_view_cyphers=self._graph_view_cyphers,
            )

        async def _fireteam_collect(state, config=None):
            return await fireteam_collect_node(
                state, config,
                llm=self.llm,
                neo4j_creds=neo4j_creds,
                streaming_callbacks=self._streaming_callbacks,
            )

        async def _process_fireteam_confirmation(state, config=None):
            return await process_fireteam_confirmation_node(state, config)

        builder.add_node("initialize", _initialize)
        builder.add_node("think", _think)
        builder.add_node("execute_tool", _execute_tool)
        builder.add_node("execute_plan", _execute_plan)
        builder.add_node("await_approval", _await_approval)
        builder.add_node("process_approval", _process_approval)
        builder.add_node("await_question", _await_question)
        builder.add_node("process_answer", _process_answer)
        builder.add_node("generate_response", _generate_response)
        builder.add_node("await_tool_confirmation", _await_tool_confirmation)
        builder.add_node("process_tool_confirmation", _process_tool_confirmation)
        builder.add_node("deploy_fireteam", _deploy_fireteam)
        builder.add_node("fireteam_collect", _fireteam_collect)
        builder.add_node("process_fireteam_confirmation", _process_fireteam_confirmation)

        # Entry point
        builder.add_edge(START, "initialize")

        # Route after initialize - process approval, process answer, process tool confirmation, or think
        builder.add_conditional_edges(
            "initialize",
            self._route_after_initialize,
            {
                "process_approval": "process_approval",
                "process_answer": "process_answer",
                "process_tool_confirmation": "process_tool_confirmation",
                "process_fireteam_confirmation": "process_fireteam_confirmation",
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Main routing from think node
        builder.add_conditional_edges(
            "think",
            self._route_after_think,
            {
                "execute_tool": "execute_tool",
                "execute_plan": "execute_plan",
                "deploy_fireteam": "deploy_fireteam",
                "await_approval": "await_approval",
                "await_question": "await_question",
                "await_tool_confirmation": "await_tool_confirmation",
                "generate_response": "generate_response",
                "think": "think",
            }
        )

        # Tool execution flow — goes directly back to think (analysis merged into think node)
        builder.add_edge("execute_tool", "think")
        builder.add_edge("execute_plan", "think")

        # Fireteam deploy flow: deploy_fireteam -> fireteam_collect -> (think | await_tool_confirmation)
        # When collect sets awaiting_tool_confirmation (escalation from a
        # member), short-circuit to await_tool_confirmation; think would
        # otherwise burn a wasted LLM call before the router pauses.
        builder.add_edge("deploy_fireteam", "fireteam_collect")
        builder.add_conditional_edges(
            "fireteam_collect",
            self._route_after_fireteam_collect,
            {
                "await_tool_confirmation": "await_tool_confirmation",
                "think": "think",
            }
        )

        # Process fireteam confirmation: after operator approves/rejects an escalation,
        # redeploy as a single-member fireteam (approve) or go back to think (reject).
        # Also routes back to await_tool_confirmation when a reject drains the
        # next queued escalation from the same wave (FIRETEAM.md §20 Q3).
        # See FIRETEAM.md §7.3.
        builder.add_conditional_edges(
            "process_fireteam_confirmation",
            self._route_after_tool_confirmation,
            {
                "deploy_fireteam": "deploy_fireteam",
                "execute_tool": "execute_tool",
                "execute_plan": "execute_plan",
                "await_tool_confirmation": "await_tool_confirmation",
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Approval flow - pause for user input
        builder.add_edge("await_approval", END)

        # Process approval routes back to think or ends
        builder.add_conditional_edges(
            "process_approval",
            self._route_after_approval,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Q&A flow - pause for user input
        builder.add_edge("await_question", END)

        # Process answer routes back to think or ends
        builder.add_conditional_edges(
            "process_answer",
            self._route_after_answer,
            {
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Tool confirmation flow - pause for user input
        builder.add_edge("await_tool_confirmation", END)

        # Process tool confirmation routes to execute, think, or ends.
        # `fireteam_deploy` is included because `_route_after_tool_confirmation`
        # is shared with process_fireteam_confirmation; LangGraph validates
        # every possible return of the router against each edge map at
        # compile time. A non-fireteam confirmation never hits that branch.
        builder.add_conditional_edges(
            "process_tool_confirmation",
            self._route_after_tool_confirmation,
            {
                "deploy_fireteam": "deploy_fireteam",
                "execute_tool": "execute_tool",
                "execute_plan": "execute_plan",
                "await_tool_confirmation": "await_tool_confirmation",
                "think": "think",
                "generate_response": "generate_response",
            }
        )

        # Final response always ends
        builder.add_edge("generate_response", END)

        self.graph = builder.compile(checkpointer=checkpointer)
        logger.info("ReAct LangGraph compiled with checkpointer")

    # =========================================================================
    # ROUTING FUNCTIONS
    # =========================================================================

    def _route_after_initialize(self, state: AgentState) -> str:
        """Route after initialization - process approval, process answer, tool confirmation, guardrail block, or think."""
        if state.get("tool_confirmation_response") and state.get("tool_confirmation_pending"):
            # Fireteam-escalated confirmation has its own post-approval handler.
            if state.get("_tool_confirmation_mode") == "fireteam_escalation":
                logger.info("Routing to process_fireteam_confirmation - fireteam escalation response pending")
                return "process_fireteam_confirmation"
            logger.info("Routing to process_tool_confirmation - tool confirmation response pending")
            return "process_tool_confirmation"

        if state.get("user_approval_response") and state.get("phase_transition_pending"):
            logger.info("Routing to process_approval - approval response pending")
            return "process_approval"

        if state.get("user_question_answer") and state.get("pending_question"):
            logger.info("Routing to process_answer - question answer pending")
            return "process_answer"

        # If guardrail blocked the target, skip straight to response
        if state.get("_guardrail_blocked"):
            logger.warning("Routing to generate_response - target blocked by guardrail")
            return "generate_response"

        return "think"

    def _route_after_think(self, state: AgentState) -> str:
        """Route based on think node decision."""
        if state.get("current_iteration", 0) >= state.get("max_iterations", get_setting('MAX_ITERATIONS', 100)):
            logger.info("Max iterations reached, generating response")
            return "generate_response"

        if state.get("task_complete"):
            return "generate_response"

        if state.get("awaiting_tool_confirmation"):
            return "await_tool_confirmation"

        if state.get("awaiting_user_approval"):
            return "await_approval"

        if state.get("awaiting_user_question"):
            return "await_question"

        decision = state.get("_decision", {})
        action = decision.get("action", "use_tool")
        tool_name = decision.get("tool_name")

        if action == "complete":
            return "generate_response"
        elif action == "ask_user":
            if state.get("pending_question"):
                return "await_question"
            else:
                logger.warning("ask_user action but no pending_question, continuing to think")
                return "generate_response"
        elif action == "transition_phase":
            if state.get("phase_transition_pending"):
                return "await_approval"
            if state.get("_just_transitioned_to"):
                logger.info(f"Phase auto-approved to {state.get('_just_transitioned_to')}, continuing to think")
                return "think"
            if tool_name:
                logger.info(f"Transition ignored, executing tool: {tool_name}")
                return "execute_tool"
            else:
                # A redundant/ignored transition (e.g. requesting the phase you are
                # already in) must NOT end the run — loop back to think so the agent
                # continues its workflow. Terminating here silently killed solvable
                # runs that re-requested transition_phase after already transitioning.
                logger.info("Transition ignored and no tool, looping back to think")
                return "think"
        elif action == "plan_tools":
            if decision.get("tool_plan"):
                return "execute_plan"
            else:
                logger.warning(f"action=plan_tools but no tool_plan in decision, falling back to generate_response")
                return "generate_response"
        elif action == "deploy_fireteam":
            # Gates (FIRETEAM_ENABLED, PERSISTENT_CHECKPOINTER, allowed_phases)
            # are enforced at think-time; by the time action survives to the
            # router, it is safe to dispatch. If no plan is present, return
            # to think (defensive — think normally attaches _current_fireteam_plan).
            if state.get("_current_fireteam_plan"):
                return "deploy_fireteam"
            logger.warning("deploy_fireteam but no _current_fireteam_plan in state; falling back to think")
            return "think"
        elif action == "switch_skill":
            # think_node already applied (or rejected, with feedback) the skill
            # switch and wrote any attack_path_type change into state. Loop back
            # to think so the agent acts under the (possibly new) skill workflow.
            return "think"
        elif action == "use_tool" and tool_name:
            return "execute_tool"
        else:
            logger.warning(f"No valid action in decision: {action}, tool: {tool_name}")
            return "generate_response"

    def _route_after_approval(self, state: AgentState) -> str:
        """Route after processing approval."""
        if state.get("task_complete"):
            return "generate_response"
        if state.get("_abort_transition"):
            return "generate_response"
        return "think"

    def _route_after_answer(self, state: AgentState) -> str:
        """Route after processing user's answer to a question."""
        if state.get("task_complete"):
            return "generate_response"
        return "think"

    def _route_after_fireteam_collect(self, state: AgentState) -> str:
        """Route after fireteam_collect merges member results.

        If a member escalated a dangerous tool request, collect set
        awaiting_tool_confirmation=True; pause the parent immediately
        instead of running think (which would burn an LLM call).
        """
        if state.get("awaiting_tool_confirmation"):
            return "await_tool_confirmation"
        return "think"

    def _route_after_tool_confirmation(self, state: AgentState) -> str:
        """Route after processing tool confirmation response."""
        if state.get("task_complete"):
            return "generate_response"
        # Queued next escalation from the same wave: re-pause for operator.
        # process_fireteam_confirmation_node sets this when rejecting but more
        # escalations remain in _pending_escalations (FIRETEAM.md §20 Q3).
        if (
            state.get("_tool_confirmation_mode") == "fireteam_escalation"
            and state.get("awaiting_tool_confirmation")
            and state.get("tool_confirmation_pending")
        ):
            return "await_tool_confirmation"
        if state.get("_reject_tool"):
            return "think"
        # Fireteam escalation approved: redeploy as a single-member fireteam
        # (per FIRETEAM.md §7.3). Do NOT fall through to execute_plan — that
        # would hijack the parent with the approved tools and detach them
        # from the originating fireteam wave in the UI.
        if state.get("_tool_confirmation_mode") == "fireteam_redeploy":
            return "deploy_fireteam"
        # Rejection from process_fireteam_confirmation (no _reject_tool set
        # but also no plan to redeploy): go back to think.
        if (
            state.get("_current_fireteam_plan") is None
            and state.get("_tool_confirmation_mode") is None
            and not state.get("_current_step")
            and not state.get("_current_plan")
        ):
            return "think"
        if state.get("_tool_confirmation_mode") == "plan":
            return "execute_plan"
        return "execute_tool"

    # =========================================================================
    # PUBLIC API
    # =========================================================================

    async def invoke(
        self,
        question: str,
        user_id: str,
        project_id: str,
        session_id: str,
        tenant_user_id: Optional[str] = None,
    ) -> InvokeResponse:
        """Main entry point for agent invocation. `tenant_user_id`: create_config."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        # Fail fast: if no LLM could be configured, return an error immediately
        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Invoking with: {question[:10000]}")

        try:
            config = create_config(user_id, project_id, session_id, tenant_user_id)
            input_data = {
                # A node-scoped question carries scanner text: fenced (B20).
                "messages": [HumanMessage(content=fence_node_context(question))]
            }

            async with self._mcp_toolset_lease(user_id):
                final_state = await self.graph.ainvoke(input_data, config)

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Error: {e}")
            return InvokeResponse(error=str(e))

    def _build_response(self, state: dict) -> InvokeResponse:
        """Build InvokeResponse from final state."""
        final_answer = ""
        tool_used = None
        tool_output = None

        messages = state.get("messages", [])
        for msg in reversed(messages):
            if isinstance(msg, AIMessage):
                final_answer = msg.content
                break

        step = state.get("_current_step", {})
        if step:
            tool_used = step.get("tool_name")
            tool_output = step.get("tool_output")

        # Check plan state if no single tool was found
        plan = state.get("_current_plan")
        if plan and not tool_used:
            for s in reversed(plan.get("steps", [])):
                if s.get("tool_name"):
                    tool_used = s["tool_name"]
                    tool_output = s.get("tool_output")
                    break

        return InvokeResponse(
            answer=final_answer,
            tool_used=tool_used,
            tool_output=tool_output,
            current_phase=state.get("current_phase", "informational"),
            iteration_count=state.get("current_iteration", 0),
            task_complete=state.get("task_complete", False),
            todo_list=state.get("todo_list", []),
            execution_trace_summary=summarize_trace_for_response(
                state.get("execution_trace", [])
            ),
            awaiting_approval=state.get("awaiting_user_approval", False),
            approval_request=state.get("phase_transition_pending"),
            awaiting_question=state.get("awaiting_user_question", False),
            question_request=state.get("pending_question"),
            awaiting_tool_confirmation=state.get("awaiting_tool_confirmation", False),
            tool_confirmation_request=state.get("tool_confirmation_pending"),
        )

    async def _report_llm_unavailable(self, streaming_callback, user_id: str,
                                      project_id: str, session_id: str) -> InvokeResponse:
        """Fail a run whose model could not be built, saying which failure it was.

        "No key" is only the message when a key or provider row is really
        missing; any other build failure names the model and the exception's
        class (llm_setup_failed), so a broken provider is not read as a missing key.
        """
        failure = getattr(self, "llm_setup_failure", None) or {}
        if failure.get("code") == "llm_setup_failed":
            msg = (f"Could not set up the model {failure.get('model')}. "
                   "Check its provider in Global Settings.")
        else:
            msg = "LLM not configured. Please add an API key in Global Settings."
            failure = {"code": "llm_not_configured", **failure}
        logger.error(f"[{user_id}/{project_id}/{session_id}] {msg} {failure}")
        await streaming_callback.on_error(msg, recoverable=False, **failure)
        return InvokeResponse(error=msg)

    async def _report_run_failure(self, streaming_callback, msg: str,
                                  exc: BaseException) -> InvokeResponse:
        """Fail a run with its exception's class and provider HTTP status, never
        its text: a provider message can quote a key, the prompt or target data.
        A run refused for the MCP toolset says so with its own code."""
        if isinstance(exc, McpToolsetBusy):
            await streaming_callback.on_error(str(exc), recoverable=False, code=exc.code)
            return InvokeResponse(error=str(exc))
        from llm_builder import provider_error_details
        await streaming_callback.on_error(
            msg, recoverable=False, code="agent_run_failed", **provider_error_details(exc))
        return InvokeResponse(error=msg)

    async def _refuse_resume(self, streaming_callback, exc: McpToolsetBusy,
                             kind: str, pending) -> InvokeResponse:
        """A refused resume leaves the run paused on the same request: the answer was
        neither applied nor saved, so the refusal is recoverable and the request is
        shown again for the person to answer once the other run has finished."""
        await streaming_callback.on_error(
            MCP_TOOLSET_BUSY_RESUME_MESSAGE, recoverable=True, code=exc.code)
        resend = getattr(streaming_callback, "resend_pending_request", None)
        if pending and resend is not None:
            await resend(kind, pending)
        return InvokeResponse(error=MCP_TOOLSET_BUSY_RESUME_MESSAGE)

    async def _refuse_stray_answer(self, config, session_id: str, field: str, kind: str,
                                   streaming_callback) -> Optional[InvokeResponse]:
        """Refuse an answer whose request (`field` of the run's state) is no longer pending.

        Another tab answered it, or a newer message dropped it. Stored, such an answer would
        hide the next request of its kind (the stream skips a request that already has an
        answer) and the next message would apply it, unchecked and unaudited. Called before
        the resume registers its callback, so a live run of the session keeps its own, and
        before on_admitted, so nothing is saved or audited. An empty session, or a read that
        fails, is left to the resume's own read, which reports it.
        """
        try:
            state = await self.graph.aget_state(config)
        except Exception:
            return None
        values = state.values if state else None
        if not values or values.get(field):
            return None
        logger.warning("[%s] %s answer refused: no pending request", session_id, kind)
        await streaming_callback.on_error(
            NO_PENDING_REQUEST_MESSAGE, recoverable=True, code="no_pending_request", answer=kind)
        return InvokeResponse(error=NO_PENDING_REQUEST_MESSAGE)

    # =========================================================================
    # STREAMING PUBLIC API
    # =========================================================================

    @asynccontextmanager
    async def _mcp_toolset_lease(self, user_id: str):
        """Hold the agent's user MCP toolset for this run (RBAC OQ-41, NF-06).

        Raises McpToolsetBusy when the run's owner's server set is not the loaded
        one and another owner's run on a different set is live. Admission and the
        lease are one synchronous step; then the owner's set is loaded (after any
        load already queued) and only then does the run go on, so it never sees or
        calls a tool of a set it was not admitted on.
        """
        servers = get_setting('USER_MCP_SERVERS', []) or []
        lease = toolset_guard().admit_run(user_id, servers)
        try:
            await self._ensure_mcp_toolset(servers, user_id)
            yield
        finally:
            toolset_guard().release_run(lease)

    async def _stream_graph(self, graph_input, config, streaming_callback,
                            user_id: str, project_id: str, session_id: str, on_admitted=None):
        """Run the graph with streaming inside a run scope; return the final state.

        The scope lets an Agent in the Loop model open steps for this session
        (and only while it runs), and reports the run's end state to its driver.
        For a provider model it only registers the run. The run holds the user MCP
        toolset for as long as it streams, and streams only once its owner's set is
        loaded (_mcp_toolset_lease). `on_admitted` runs once the run is admitted and
        its set loaded: a resume saves the person's answer there, never before.
        """
        uses_loop = is_loop_llm(self.llm)
        final_state = None
        async with self._mcp_toolset_lease(user_id):
            if on_admitted is not None:
                on_admitted()
            # Every node and Fireteam member runs in a task created inside astream,
            # so it inherits this listener and a rate-limit wait reaches the drawer.
            listener = current_llm_wait_listener.set(
                getattr(streaming_callback, "on_rate_limit_wait", None))
            try:
                async with get_broker().run_scope(
                        user_id, project_id, session_id, streaming_callback, uses_loop=uses_loop,
                        tool_confirmation=bool(get_setting('REQUIRE_TOOL_CONFIRMATION', True))) as scope:
                    async for event in self.graph.astream(graph_input, config, stream_mode="values"):
                        final_state = event
                        scope.final_state = event
                        await emit_streaming_events(event, streaming_callback)
            finally:
                current_llm_wait_listener.reset(listener)
        return final_state

    async def invoke_with_streaming(
        self,
        question: str,
        user_id: str,
        project_id: str,
        session_id: str,
        streaming_callback,
        guidance_queue=None,
        graph_view_cypher=None,
        tenant_user_id: Optional[str] = None,
    ) -> InvokeResponse:
        """
        Invoke agent with streaming callbacks for real-time updates.

        `user_id` is the person running the session (the thread, the chat, the run
        and the Agent in the Loop scope are theirs); `tenant_user_id` the project's
        owner, whose graph the nodes read and write (create_config). Every resume
        below takes the same pair.

        The streaming_callback should have methods:
        - on_thinking(iteration, phase, thought, reasoning)
        - on_tool_start(tool_name, tool_args)
        - on_tool_output_chunk(tool_name, chunk, is_final)
        - on_tool_complete(tool_name, success, output_summary)
        - on_phase_update(current_phase, iteration_count)
        - on_todo_update(todo_list)
        - on_approval_request(approval_request)
        - on_question_request(question_request)
        - on_response(answer, iteration_count, phase, task_complete)
        - on_execution_step(step)
        - on_error(error_message, recoverable)
        - on_task_complete(message, final_phase, total_iterations)
        """
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        # Fail fast: if no LLM could be configured, return an error immediately
        # instead of letting the guardrail's fail-closed mask it as "Target Blocked".
        # The same read the graph nodes make: this run's own client.
        if self.llm is None:
            return await self._report_llm_unavailable(streaming_callback, user_id, project_id, session_id)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Invoking with streaming: {question[:10000]}")

        # Store streaming callback, guidance queue, and graph view scope per-session
        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue
        self._graph_view_cyphers[session_id] = graph_view_cypher

        try:
            config = create_config(user_id, project_id, session_id, tenant_user_id)
            input_data = clear_stale_streaming_state({
                # A node-scoped question carries scanner text: fenced (B20).
                "messages": [HumanMessage(content=fence_node_context(question))],
                **_NO_ANSWER,
            })

            # Stream graph execution
            final_state = await self._stream_graph(
                input_data, config, streaming_callback, user_id, project_id, session_id)

            if final_state:
                response = self._build_response(final_state)
                # Don't send response when graph paused for user interaction
                is_paused = (
                    final_state.get("awaiting_tool_confirmation")
                    or final_state.get("awaiting_user_approval")
                    or final_state.get("awaiting_user_question")
                )
                if not is_paused:
                    await streaming_callback.on_response(
                        response.answer,
                        response.iteration_count,
                        response.current_phase,
                        response.task_complete,
                        response_tier=final_state.get("_response_tier", "full_report"),
                    )
                return response
            else:
                raise RuntimeError("No final state returned from graph execution")

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Streaming error: {e}", exc_info=True)
            return await self._report_run_failure(streaming_callback, "The agent run failed", e)
        finally:
            self._streaming_callbacks.pop(session_id, None)
            self._guidance_queues.pop(session_id, None)
            self._graph_view_cyphers.pop(session_id, None)

    async def resume_after_approval_with_streaming(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modification: Optional[str],
        streaming_callback,
        guidance_queue=None,
        on_admitted=None,
        tenant_user_id: Optional[str] = None,
    ) -> InvokeResponse:
        """Resume after approval with streaming callbacks. `on_admitted` saves the
        decision once the run is admitted (_stream_graph)."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            return await self._report_llm_unavailable(streaming_callback, user_id, project_id, session_id)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming approval: {decision}")

        refusal = await self._refuse_stray_answer(
            create_config(user_id, project_id, session_id, tenant_user_id), session_id,
            "phase_transition_pending", "approval", streaming_callback)
        if refusal is not None:
            return refusal

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        pending = None
        try:
            config = create_config(user_id, project_id, session_id, tenant_user_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")
            pending = current_state.values.get("phase_transition_pending")

            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
                # Clear stale fields to prevent duplicate emissions from
                # fresh StreamingCallback (same pattern as tool confirmation).
                "_decision": None,
                "_completed_step": None,
            }

            final_state = await self._stream_graph(
                update_data, config, streaming_callback, user_id, project_id, session_id,
                on_admitted=on_admitted)

            if final_state:
                response = self._build_response(final_state)
                is_paused = (
                    final_state.get("awaiting_tool_confirmation")
                    or final_state.get("awaiting_user_approval")
                    or final_state.get("awaiting_user_question")
                )
                if not is_paused:
                    await streaming_callback.on_response(
                        response.answer,
                        response.iteration_count,
                        response.current_phase,
                        response.task_complete,
                        response_tier=final_state.get("_response_tier", "full_report"),
                    )
                return response
            else:
                raise RuntimeError("No final state returned")

        except McpToolsetBusy as e:
            return await self._refuse_resume(streaming_callback, e, "approval", pending)
        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            return await self._report_run_failure(streaming_callback, "The agent run failed after the approval", e)
        finally:
            self._streaming_callbacks.pop(session_id, None)
            self._guidance_queues.pop(session_id, None)
            self._graph_view_cyphers.pop(session_id, None)

    async def resume_after_answer_with_streaming(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        answer: str,
        streaming_callback,
        guidance_queue=None,
        on_admitted=None,
        tenant_user_id: Optional[str] = None,
    ) -> InvokeResponse:
        """Resume after answer with streaming callbacks. `on_admitted` saves the
        answer once the run is admitted (_stream_graph)."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            return await self._report_llm_unavailable(streaming_callback, user_id, project_id, session_id)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming answer: {answer[:10000]}")

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        pending = None
        try:
            config = create_config(user_id, project_id, session_id, tenant_user_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")
            pending = current_state.values.get("pending_question")

            update_data = {
                "user_question_answer": answer,
                # Clear stale fields to prevent duplicate emissions from
                # fresh StreamingCallback (same pattern as tool confirmation).
                "_decision": None,
                "_completed_step": None,
            }

            final_state = await self._stream_graph(
                update_data, config, streaming_callback, user_id, project_id, session_id,
                on_admitted=on_admitted)

            if final_state:
                response = self._build_response(final_state)
                is_paused = (
                    final_state.get("awaiting_tool_confirmation")
                    or final_state.get("awaiting_user_approval")
                    or final_state.get("awaiting_user_question")
                )
                if not is_paused:
                    await streaming_callback.on_response(
                        response.answer,
                        response.iteration_count,
                        response.current_phase,
                        response.task_complete,
                        response_tier=final_state.get("_response_tier", "full_report"),
                    )
                return response
            else:
                raise RuntimeError("No final state returned")

        except McpToolsetBusy as e:
            return await self._refuse_resume(streaming_callback, e, "question", pending)
        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            return await self._report_run_failure(streaming_callback, "The agent run failed after the answer", e)
        finally:
            self._streaming_callbacks.pop(session_id, None)
            self._guidance_queues.pop(session_id, None)
            self._graph_view_cyphers.pop(session_id, None)

    async def resume_after_tool_confirmation_with_streaming(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modifications: Optional[dict],
        streaming_callback,
        guidance_queue=None,
        on_admitted=None,
        tenant_user_id: Optional[str] = None,
    ) -> InvokeResponse:
        """Resume after tool confirmation with streaming callbacks. `on_admitted`
        saves the decision once the run is admitted (_stream_graph)."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            return await self._report_llm_unavailable(streaming_callback, user_id, project_id, session_id)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming tool confirmation: {decision}")

        refusal = await self._refuse_stray_answer(
            create_config(user_id, project_id, session_id, tenant_user_id), session_id,
            "tool_confirmation_pending", "tool_confirmation", streaming_callback)
        if refusal is not None:
            return refusal

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        pending = None
        try:
            config = create_config(user_id, project_id, session_id, tenant_user_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")
            pending = current_state.values.get("tool_confirmation_pending")

            update_data = {
                "tool_confirmation_response": decision,
                "tool_confirmation_modification": modifications,
                # Clear stale fields BEFORE astream starts — the first state
                # yield is the checkpoint state (before process_tool_confirmation
                # runs), and a new StreamingCallback has empty dedup sets, so
                # stale _decision / _completed_step would be re-emitted as
                # duplicate THINKING / TOOL_COMPLETE events.
                "_decision": None,
                "_completed_step": None,
            }

            final_state = await self._stream_graph(
                update_data, config, streaming_callback, user_id, project_id, session_id,
                on_admitted=on_admitted)

            if final_state:
                response = self._build_response(final_state)
                is_paused = (
                    final_state.get("awaiting_tool_confirmation")
                    or final_state.get("awaiting_user_approval")
                    or final_state.get("awaiting_user_question")
                )
                if not is_paused:
                    await streaming_callback.on_response(
                        response.answer,
                        response.iteration_count,
                        response.current_phase,
                        response.task_complete,
                        response_tier=final_state.get("_response_tier", "full_report"),
                    )
                return response
            else:
                raise RuntimeError("No final state returned")

        except McpToolsetBusy as e:
            return await self._refuse_resume(streaming_callback, e, "tool_confirmation", pending)
        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            return await self._report_run_failure(streaming_callback, "The agent run failed after the tool confirmation", e)
        finally:
            self._streaming_callbacks.pop(session_id, None)
            self._guidance_queues.pop(session_id, None)
            self._graph_view_cyphers.pop(session_id, None)

    async def resume_execution_with_streaming(
        self,
        user_id: str,
        project_id: str,
        session_id: str,
        streaming_callback,
        guidance_queue=None,
        tenant_user_id: Optional[str] = None,
    ) -> InvokeResponse:
        """Resume execution from last checkpoint (after stop)."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            return await self._report_llm_unavailable(streaming_callback, user_id, project_id, session_id)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming execution from checkpoint")

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        try:
            config = create_config(user_id, project_id, session_id, tenant_user_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No session state to resume", recoverable=False)
                return InvokeResponse(error="No session state to resume")

            # Re-invoke graph from last checkpoint with empty input
            final_state = await self._stream_graph(
                {}, config, streaming_callback, user_id, project_id, session_id)

            if final_state:
                response = self._build_response(final_state)
                is_paused = (
                    final_state.get("awaiting_tool_confirmation")
                    or final_state.get("awaiting_user_approval")
                    or final_state.get("awaiting_user_question")
                )
                if not is_paused:
                    await streaming_callback.on_response(
                        response.answer,
                        response.iteration_count,
                        response.current_phase,
                        response.task_complete,
                        response_tier=final_state.get("_response_tier", "full_report"),
                    )
                return response
            else:
                raise RuntimeError("No final state returned")

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume execution error: {e}")
            return await self._report_run_failure(streaming_callback, "The agent run failed while resuming", e)
        finally:
            self._streaming_callbacks.pop(session_id, None)
            self._guidance_queues.pop(session_id, None)
            self._graph_view_cyphers.pop(session_id, None)

    async def close(self) -> None:
        """Clean up resources."""
        # Close KB Neo4j driver if it was created
        kb = getattr(self, '_knowledge_base', None)
        if kb is not None and getattr(kb, 'neo4j', None) is not None:
            try:
                driver = getattr(kb.neo4j, 'driver', None)
                if driver is not None:
                    driver.close()
                    logger.debug("Knowledge base Neo4j driver closed")
            except Exception as e:
                logger.warning(f"Error closing KB Neo4j driver: {e}")

        self._initialized = False
        logger.info("AgentOrchestrator closed")
