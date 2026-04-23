"""
RedAmon Agent Orchestrator

ReAct-style agent orchestrator with iterative Thought-Tool-Output pattern.
Supports phase tracking, LLM-managed todo lists, and checkpoint-based approval.
"""

import asyncio
import os
import logging
from typing import Optional

from langchain_core.language_models import BaseChatModel
from langchain_core.messages import AIMessage, HumanMessage
from langgraph.graph import StateGraph, START, END
from langgraph.checkpoint.memory import MemorySaver

from state import (
    AgentState,
    InvokeResponse,
    summarize_trace_for_response,
)
from project_settings import get_setting
from key_rotation import KeyRotator
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
from orchestrator_helpers.llm_setup import setup_llm, apply_project_settings
from orchestrator_helpers.streaming import emit_streaming_events
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

        self.model_name: Optional[str] = None
        self.llm: Optional[BaseChatModel] = None
        self.tool_executor: Optional[PhaseAwareToolExecutor] = None
        self.neo4j_manager: Optional[Neo4jToolManager] = None
        self.graph = None

        self._initialized = False
        # Per-session maps — keyed by session_id so concurrent sessions
        # don't overwrite each other's callback / guidance queue.
        self._streaming_callbacks: dict[str, object] = {}
        self._guidance_queues: dict[str, asyncio.Queue] = {}
        self._graph_view_cyphers: dict[str, str | None] = {}

        # Metasploit prewarm: background restart tasks keyed by session_key
        self._prewarm_tasks: dict[str, asyncio.Task] = {}

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

    def start_msf_prewarm(self, session_key: str) -> None:
        """
        Start a background Metasploit restart so msfconsole is ready
        by the time the agent needs it.

        Called on WebSocket init (drawer open). Fire-and-forget.
        If a prewarm is already running for this session, skip.
        """
        if not self._initialized or not self.tool_executor:
            logger.debug("Orchestrator not initialized yet, skipping prewarm")
            return

        # Skip if already running for this session
        existing = self._prewarm_tasks.get(session_key)
        if existing and not existing.done():
            logger.debug(f"Prewarm already running for {session_key}, skipping")
            return

        logger.info(f"[{session_key}] Starting Metasploit prewarm (background)")
        task = asyncio.create_task(self._do_msf_prewarm(session_key))
        self._prewarm_tasks[session_key] = task

    async def _do_msf_prewarm(self, session_key: str) -> None:
        """Background task: restart msfconsole for a clean state."""
        try:
            result = await self.tool_executor.execute(
                "msf_restart", {}, "exploitation", skip_phase_check=True
            )
            if result and result.get("success"):
                logger.info(f"[{session_key}] Metasploit prewarm complete")
            else:
                logger.warning(f"[{session_key}] Metasploit prewarm failed: {result}")
        except asyncio.CancelledError:
            logger.info(f"[{session_key}] Metasploit prewarm cancelled")
        except Exception as e:
            logger.warning(f"[{session_key}] Metasploit prewarm error: {e}")
        finally:
            # Clean up the task reference
            self._prewarm_tasks.pop(session_key, None)

    # =========================================================================
    # LLM & PROJECT SETTINGS
    # =========================================================================

    def _apply_project_settings(self, project_id: str) -> None:
        """Load project settings and reconfigure LLM if model changed."""
        apply_project_settings(self, project_id)

        # Update tool API keys and rotation from user settings
        user_settings = getattr(self, '_user_settings', {})
        rotation_configs = user_settings.get('rotationConfigs', {})

        def _build_rotator(main_key: str, tool_name: str) -> KeyRotator:
            cfg = rotation_configs.get(tool_name, {})
            extra = cfg.get('extraKeys', [])
            rotate_n = cfg.get('rotateEveryN', 10)
            return KeyRotator([main_key] + extra, rotate_n)

        # Tavily (web_search)
        tavily_key = user_settings.get('tavilyApiKey', '')
        if tavily_key and self._web_search_manager and self._web_search_manager.api_key != tavily_key:
            self._web_search_manager.api_key = tavily_key
            new_tool = self._web_search_manager.get_tool()
            if new_tool and self.tool_executor:
                self.tool_executor.update_web_search_tool(new_tool)
                logger.info("Updated Tavily web search tool with user settings key")
        if tavily_key and self._web_search_manager:
            self._web_search_manager.key_rotator = _build_rotator(tavily_key, 'tavily')

        # Knowledge Base — apply per-project settings.
        #
        # Precedence: per-project value (non-None) > kb_config.yaml
        # (loaded into the KB instance at construction time) > kb_config.py
        # DEFAULTS. We only mutate live KB attributes when the
        # project-level setting is non-None, so a None sentinel in
        # DEFAULT_AGENT_SETTINGS preserves whatever the YAML loaded —
        # the common case for operators who tune via kb_config.yaml and
        # never touch the webapp UI.
        if getattr(self, '_knowledge_base', None) and self._web_search_manager:
            kb_enabled = get_setting('KB_ENABLED', None)
            # None → inherit (default True from kb_config.yaml KB_ENABLED).
            # False → explicit disable. True → explicit enable.
            if kb_enabled is not False:
                kb = self._knowledge_base

                score_threshold = get_setting('KB_SCORE_THRESHOLD', None)
                if score_threshold is not None:
                    kb.score_threshold = score_threshold

                top_k = get_setting('KB_TOP_K', None)
                if top_k is not None:
                    kb.top_k = top_k

                # Ranking knobs (source boost + MMR diversity)
                mmr_enabled = get_setting('KB_MMR_ENABLED', None)
                if mmr_enabled is not None:
                    kb.mmr_enabled = mmr_enabled

                mmr_lambda = get_setting('KB_MMR_LAMBDA', None)
                if mmr_lambda is not None:
                    kb.mmr_lambda = mmr_lambda

                overfetch_factor = get_setting('KB_OVERFETCH_FACTOR', None)
                if overfetch_factor is not None:
                    kb.overfetch_factor = overfetch_factor

                custom_boosts = get_setting('KB_SOURCE_BOOSTS', None)
                if custom_boosts:
                    # Merge user overrides on top of whatever the KB
                    # already loaded from kb_config.yaml source_boosts.
                    # This preserves per-source tunings from the YAML
                    # for sources the webapp override doesn't mention.
                    existing = getattr(kb, 'source_boosts', None) or {}
                    kb.source_boosts = {**existing, **custom_boosts}

                self._web_search_manager.knowledge_base = kb
                self._web_search_manager.kb_enabled_sources = get_setting(
                    'KB_ENABLED_SOURCES', None
                )
            else:
                # Project explicitly disabled KB — detach from web search
                self._web_search_manager.knowledge_base = None
                self._web_search_manager.kb_enabled_sources = None
            # Rebuild web_search tool to reflect new KB state
            new_tool = self._web_search_manager.get_tool()
            if new_tool and self.tool_executor:
                self.tool_executor.update_web_search_tool(new_tool)

        # Shodan
        shodan_key = user_settings.get('shodanApiKey', '')
        if self._shodan_manager and self.tool_executor:
            shodan_enabled = get_setting('SHODAN_ENABLED', True)
            if shodan_key and shodan_enabled and self._shodan_manager.api_key != shodan_key:
                self._shodan_manager.api_key = shodan_key
                shodan_tool = self._shodan_manager.get_tool()
                self.tool_executor.update_shodan_tool(shodan_tool)
                logger.info("Updated Shodan OSINT tool with user settings key")
            elif not shodan_enabled:
                self.tool_executor.update_shodan_tool(None)
                logger.info("Shodan tool disabled via project settings")
        if shodan_key and self._shodan_manager:
            self._shodan_manager.key_rotator = _build_rotator(shodan_key, 'shodan')

        # WPScan API token (injected silently into execute_wpscan args)
        wpscan_token = user_settings.get('wpscanApiToken', '')
        if wpscan_token and self.tool_executor:
            self.tool_executor.set_wpscan_api_token(wpscan_token)
            logger.info("WPScan API token configured for vulnerability enrichment")

        # URLScan API key (injected silently into execute_gau config)
        urlscan_key = user_settings.get('urlscanApiKey', '')
        if urlscan_key and self.tool_executor:
            self.tool_executor.set_gau_urlscan_api_key(urlscan_key)
            logger.info("URLScan API key configured for GAU enrichment")

        # Google dork (SerpAPI)
        serp_api_key = user_settings.get('serpApiKey', '')
        if self._google_dork_manager and self.tool_executor:
            if serp_api_key and self._google_dork_manager.api_key != serp_api_key:
                self._google_dork_manager.api_key = serp_api_key
                google_dork_tool = self._google_dork_manager.get_tool()
                self.tool_executor.update_google_dork_tool(google_dork_tool)
                logger.info("Updated Google dork tool with SerpAPI key")
        if serp_api_key and self._google_dork_manager:
            self._google_dork_manager.key_rotator = _build_rotator(serp_api_key, 'serp')

    def _setup_llm(self) -> None:
        """Initialize the LLM based on current model_name.

        Resolves keys from the cached project settings (if loaded)
        or from whatever user providers are available.
        """
        from project_settings import get_settings
        from orchestrator_helpers.llm_setup import _resolve_provider_key

        settings = get_settings()
        user_providers = settings.get('USER_LLM_PROVIDERS', [])
        custom_config = settings.get('CUSTOM_LLM_CONFIG')

        openai_p = _resolve_provider_key(user_providers, "openai")
        anthropic_p = _resolve_provider_key(user_providers, "anthropic")
        openrouter_p = _resolve_provider_key(user_providers, "openrouter")
        bedrock_p = _resolve_provider_key(user_providers, "bedrock")

        self.llm = setup_llm(
            self.model_name,
            openai_api_key=(openai_p or {}).get("apiKey"),
            anthropic_api_key=(anthropic_p or {}).get("apiKey"),
            openrouter_api_key=(openrouter_p or {}).get("apiKey"),
            aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
            aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
            aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
            custom_llm_config=custom_config,
        )

    # =========================================================================
    # TOOLS & GRAPH SETUP
    # =========================================================================

    async def _setup_tools(self) -> None:
        """Set up all tools (MCP and Neo4j)."""
        # Setup MCP tools
        mcp_manager = MCPToolsManager()
        mcp_tools = await mcp_manager.get_tools()

        # Setup Neo4j graph query tool (LLM is None until project settings are loaded)
        self.neo4j_manager = Neo4jToolManager(
            uri=self.neo4j_uri,
            user=self.neo4j_user,
            password=self.neo4j_password,
            llm=self.llm
        )
        graph_tool = self.neo4j_manager.get_tool()

        # Setup Knowledge Base (FAISS + Neo4j hybrid)
        self._knowledge_base = self._setup_knowledge_base()

        # If KB is not available, swap the web_search tool registry entry
        # to a simplified Tavily-only description so the LLM doesn't use
        # KB-specific parameters (include_sources, exclude_sources, min_cvss)
        if self._knowledge_base is None:
            from prompts.tool_registry import TOOL_REGISTRY, WEB_SEARCH_TAVILY_ONLY
            TOOL_REGISTRY["web_search"] = WEB_SEARCH_TAVILY_ONLY

        # Setup Tavily web search tool (key resolved later via update_tavily_key)
        # KB is passed in so web_search can check it before falling back to Tavily
        self._web_search_manager = WebSearchToolManager(
            knowledge_base=self._knowledge_base,
        )
        web_search_tool = self._web_search_manager.get_tool()

        # Setup Shodan OSINT tool (key resolved later via _apply_project_settings)
        self._shodan_manager = ShodanToolManager()
        shodan_tool = self._shodan_manager.get_tool()

        # Setup Google dork tool (key resolved later via _apply_project_settings)
        self._google_dork_manager = GoogleDorkToolManager()
        google_dork_tool = self._google_dork_manager.get_tool()

        # Create phase-aware tool executor
        self.tool_executor = PhaseAwareToolExecutor(
            mcp_manager, graph_tool, web_search_tool,
            shodan_tool, google_dork_tool,
        )
        self.tool_executor.register_mcp_tools(mcp_tools)

        logger.info(f"Tools initialized: {len(self.tool_executor.get_all_tools())} available")

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
            return await await_approval_node(state, config)

        async def _process_approval(state, config=None):
            return await process_approval_node(state, config, neo4j_creds=neo4j_creds)

        async def _await_question(state, config=None):
            return await await_question_node(state, config)

        async def _process_answer(state, config=None):
            return await process_answer_node(state, config)

        async def _generate_response(state, config=None):
            return await generate_response_node(state, config, llm=self.llm, streaming_callbacks=self._streaming_callbacks, neo4j_creds=neo4j_creds)

        async def _await_tool_confirmation(state, config=None):
            return await await_tool_confirmation_node(state, config)

        async def _process_tool_confirmation(state, config=None):
            return await process_tool_confirmation_node(state, config)

        # --- Fireteam (multi-agent) ---
        # Prebuild the member graph once. Reads self.llm at call time via
        # getter (self.llm is None here; populated by _setup_llm later).
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
                logger.info("Transition ignored and no tool, generating response")
                return "generate_response"
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
        session_id: str
    ) -> InvokeResponse:
        """Main entry point for agent invocation."""
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
            config = create_config(user_id, project_id, session_id)
            input_data = {
                "messages": [HumanMessage(content=question)]
            }

            final_state = await self.graph.ainvoke(input_data, config)

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Error: {e}")
            return InvokeResponse(error=str(e))

    async def resume_after_approval(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modification: Optional[str] = None
    ) -> InvokeResponse:
        """Resume execution after user provides approval response."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with approval: {decision}")

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)

            if not current_state or not current_state.values:
                return InvokeResponse(error="No pending session found")

            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
            }

            final_state = await self.graph.ainvoke(
                update_data,
                config,
            )

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))

    async def resume_after_answer(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        answer: str
    ) -> InvokeResponse:
        """Resume execution after user provides answer to a question."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with answer: {answer[:10000]}")

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)

            if not current_state or not current_state.values:
                return InvokeResponse(error="No pending session found")

            update_data = {
                "user_question_answer": answer,
            }

            final_state = await self.graph.ainvoke(
                update_data,
                config,
            )

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume error: {e}")
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

    # =========================================================================
    # STREAMING PUBLIC API
    # =========================================================================

    async def invoke_with_streaming(
        self,
        question: str,
        user_id: str,
        project_id: str,
        session_id: str,
        streaming_callback,
        guidance_queue=None,
        graph_view_cypher=None,
    ) -> InvokeResponse:
        """
        Invoke agent with streaming callbacks for real-time updates.

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
        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            await streaming_callback.on_error(msg, recoverable=False)
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Invoking with streaming: {question[:10000]}")

        # Store streaming callback, guidance queue, and graph view scope per-session
        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue
        self._graph_view_cyphers[session_id] = graph_view_cypher

        try:
            config = create_config(user_id, project_id, session_id)
            input_data = {
                "messages": [HumanMessage(content=question)]
            }

            # Stream graph execution
            final_state = None
            async for event in self.graph.astream(input_data, config, stream_mode="values"):
                final_state = event
                await emit_streaming_events(event, streaming_callback)

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
            logger.error(f"[{user_id}/{project_id}/{session_id}] Streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
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
        guidance_queue=None
    ) -> InvokeResponse:
        """Resume after approval with streaming callbacks."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            await streaming_callback.on_error(msg, recoverable=False)
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming approval: {decision}")

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")

            update_data = {
                "user_approval_response": decision,
                "user_modification": modification,
                # Clear stale fields to prevent duplicate emissions from
                # fresh StreamingCallback (same pattern as tool confirmation).
                "_decision": None,
                "_completed_step": None,
            }

            final_state = None
            async for event in self.graph.astream(update_data, config, stream_mode="values"):
                final_state = event
                await emit_streaming_events(event, streaming_callback)

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
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
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
        guidance_queue=None
    ) -> InvokeResponse:
        """Resume after answer with streaming callbacks."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            await streaming_callback.on_error(msg, recoverable=False)
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming answer: {answer[:10000]}")

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")

            update_data = {
                "user_question_answer": answer,
                # Clear stale fields to prevent duplicate emissions from
                # fresh StreamingCallback (same pattern as tool confirmation).
                "_decision": None,
                "_completed_step": None,
            }

            final_state = None
            async for event in self.graph.astream(update_data, config, stream_mode="values"):
                final_state = event
                await emit_streaming_events(event, streaming_callback)

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
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
        finally:
            self._streaming_callbacks.pop(session_id, None)
            self._guidance_queues.pop(session_id, None)
            self._graph_view_cyphers.pop(session_id, None)

    async def resume_after_tool_confirmation(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modifications: Optional[dict] = None
    ) -> InvokeResponse:
        """Resume execution after user provides tool confirmation response."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with tool confirmation: {decision}")

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)

            if not current_state or not current_state.values:
                return InvokeResponse(error="No pending session found")

            update_data = {
                "tool_confirmation_response": decision,
                "tool_confirmation_modification": modifications,
            }

            final_state = await self.graph.ainvoke(
                update_data,
                config,
            )

            return self._build_response(final_state)

        except Exception as e:
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume error: {e}")
            return InvokeResponse(error=str(e))

    async def resume_after_tool_confirmation_with_streaming(
        self,
        session_id: str,
        user_id: str,
        project_id: str,
        decision: str,
        modifications: Optional[dict],
        streaming_callback,
        guidance_queue=None
    ) -> InvokeResponse:
        """Resume after tool confirmation with streaming callbacks."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            await streaming_callback.on_error(msg, recoverable=False)
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming with streaming tool confirmation: {decision}")

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No pending session found", recoverable=False)
                return InvokeResponse(error="No pending session found")

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

            final_state = None
            async for event in self.graph.astream(update_data, config, stream_mode="values"):
                final_state = event
                await emit_streaming_events(event, streaming_callback)

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
            logger.error(f"[{user_id}/{project_id}/{session_id}] Resume streaming error: {e}")
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
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
        guidance_queue=None
    ) -> InvokeResponse:
        """Resume execution from last checkpoint (after stop)."""
        if not self._initialized:
            raise RuntimeError("Orchestrator not initialized. Call initialize() first.")

        self._apply_project_settings(project_id)

        if self.llm is None:
            msg = "LLM not configured. Please add an API key in Global Settings."
            logger.error(f"[{user_id}/{project_id}/{session_id}] {msg}")
            await streaming_callback.on_error(msg, recoverable=False)
            return InvokeResponse(error=msg)

        logger.info(f"[{user_id}/{project_id}/{session_id}] Resuming execution from checkpoint")

        self._streaming_callbacks[session_id] = streaming_callback
        self._guidance_queues[session_id] = guidance_queue

        try:
            config = create_config(user_id, project_id, session_id)

            current_state = await self.graph.aget_state(config)
            if not current_state or not current_state.values:
                await streaming_callback.on_error("No session state to resume", recoverable=False)
                return InvokeResponse(error="No session state to resume")

            # Re-invoke graph from last checkpoint with empty input
            final_state = None
            async for event in self.graph.astream({}, config, stream_mode="values"):
                final_state = event
                await emit_streaming_events(event, streaming_callback)

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
            await streaming_callback.on_error(str(e), recoverable=False)
            return InvokeResponse(error=str(e))
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
