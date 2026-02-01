"""
RedAmon Agent Tools

MCP tools and Neo4j graph query tool definitions.
Includes phase-aware tool management.
"""

import re
import json
import asyncio
import logging
from typing import List, Optional, Dict, Callable, Awaitable, TYPE_CHECKING
from contextvars import ContextVar

import httpx
from langchain_core.tools import tool
from langchain_mcp_adapters.client import MultiServerMCPClient
from langchain_neo4j import Neo4jGraph

from params import (
    MCP_CURL_URL,
    MCP_NAABU_URL,
    MCP_METASPLOIT_URL,
    MCP_METASPLOIT_PROGRESS_URL,
    CYPHER_MAX_RETRIES,
    is_tool_allowed_in_phase,
)
from prompts import TEXT_TO_CYPHER_SYSTEM

if TYPE_CHECKING:
    from langchain_openai import ChatOpenAI

logger = logging.getLogger(__name__)

# =============================================================================
# CONTEXT VARIABLES
# =============================================================================

# Context variables to pass user_id and project_id to tools
current_user_id: ContextVar[str] = ContextVar('current_user_id', default='')
current_project_id: ContextVar[str] = ContextVar('current_project_id', default='')
current_phase: ContextVar[str] = ContextVar('current_phase', default='informational')


def set_tenant_context(user_id: str, project_id: str) -> None:
    """Set the current user and project context for tool execution."""
    current_user_id.set(user_id)
    current_project_id.set(project_id)


def set_phase_context(phase: str) -> None:
    """Set the current phase context for tool restrictions."""
    current_phase.set(phase)


def get_phase_context() -> str:
    """Get the current phase context."""
    return current_phase.get()


# =============================================================================
# MCP TOOLS MANAGER
# =============================================================================

class MCPToolsManager:
    """Manages MCP (Model Context Protocol) tool connections."""

    def __init__(
        self,
        curl_url: str = MCP_CURL_URL,
        naabu_url: str = MCP_NAABU_URL,
        metasploit_url: str = MCP_METASPLOIT_URL,
    ):
        self.curl_url = curl_url
        self.naabu_url = naabu_url
        self.metasploit_url = metasploit_url
        self.client: Optional[MultiServerMCPClient] = None
        self._tools_cache: Dict[str, any] = {}

    async def get_tools(self) -> List:
        """
        Connect to MCP servers and load tools.

        Returns:
            List of MCP tools available for use
        """
        logger.info("Connecting to MCP servers...")

        mcp_servers = {}
        all_tools = []

        # Try to connect to each MCP server
        # Timeout settings (in seconds):
        # - timeout: HTTP connection timeout (default 5s)
        # - sse_read_timeout: How long to wait for SSE events (default 300s = 5 min)
        # Metasploit needs longer timeouts for brute force attacks (30 min for large wordlists)
        server_configs = [
            ("curl", self.curl_url, 60, 300),           # 1 min connect, 5 min read
            ("naabu", self.naabu_url, 60, 600),         # 1 min connect, 10 min read
            ("metasploit", self.metasploit_url, 60, 1800),  # 1 min connect, 30 min read
        ]

        for server_name, url, timeout, sse_read_timeout in server_configs:
            try:
                logger.info(f"Connecting to MCP {server_name} server at {url}")
                mcp_servers[server_name] = {
                    "url": url,
                    "transport": "sse",
                    "timeout": timeout,
                    "sse_read_timeout": sse_read_timeout,
                }
            except Exception as e:
                logger.warning(f"Failed to configure MCP server {server_name}: {e}")

        if not mcp_servers:
            logger.warning("No MCP servers configured")
            return []

        try:
            self.client = MultiServerMCPClient(mcp_servers)
            mcp_tools = await self.client.get_tools()

            # Cache tools by name for easy access
            for tool in mcp_tools:
                tool_name = getattr(tool, 'name', str(tool))
                self._tools_cache[tool_name] = tool
                all_tools.append(tool)

            logger.info(f"Loaded {len(all_tools)} tools from MCP servers: {list(self._tools_cache.keys())}")
            return all_tools

        except Exception as e:
            logger.error(f"Failed to connect to MCP servers: {e}")
            logger.warning("Continuing without MCP tools")
            return []

    def get_tool_by_name(self, name: str) -> Optional[any]:
        """Get a specific tool by name."""
        return self._tools_cache.get(name)

    def get_available_tools_for_phase(self, phase: str) -> List:
        """Get tools that are allowed in the current phase."""
        return [
            tool for name, tool in self._tools_cache.items()
            if is_tool_allowed_in_phase(name, phase)
        ]


# =============================================================================
# NEO4J TOOL MANAGER
# =============================================================================

class Neo4jToolManager:
    """Manages Neo4j graph query tool with tenant filtering."""

    def __init__(self, uri: str, user: str, password: str, llm: "ChatOpenAI"):
        self.uri = uri
        self.user = user
        self.password = password
        self.llm = llm
        self.graph: Optional[Neo4jGraph] = None

    def _inject_tenant_filter(self, cypher: str, user_id: str, project_id: str) -> str:
        """
        Inject mandatory user_id and project_id filters into a Cypher query.

        This ensures all queries are scoped to the current user's project,
        preventing cross-tenant data access.

        Strategy: Add tenant properties directly into each node pattern as inline
        property filters. This ensures filters are always in scope regardless of
        WITH clauses or query structure.

        Example:
            MATCH (d:Domain {name: "example.com"})
        becomes:
            MATCH (d:Domain {name: "example.com", user_id: $tenant_user_id, project_id: $tenant_project_id})

        Args:
            cypher: The AI-generated Cypher query
            user_id: Current user's ID
            project_id: Current project's ID

        Returns:
            Modified Cypher query with tenant filters applied
        """
        tenant_props = "user_id: $tenant_user_id, project_id: $tenant_project_id"

        def add_tenant_to_node(match: re.Match) -> str:
            """Add tenant properties to a node pattern."""
            var_name = match.group(1)
            label = match.group(2)
            existing_props_content = match.group(3)  # Content INSIDE braces (without braces), or None

            if existing_props_content is not None:
                # Has existing properties - merge with tenant props
                existing_props_content = existing_props_content.strip()
                if existing_props_content:
                    # Append tenant props after existing ones
                    new_props = f"{{{existing_props_content}, {tenant_props}}}"
                else:
                    new_props = f"{{{tenant_props}}}"
                return f"({var_name}:{label} {new_props})"
            else:
                # No existing properties, add them
                return f"({var_name}:{label} {{{tenant_props}}})"

        # Pattern matches: (variable:Label) or (variable:Label {props})
        # Captures: 1=variable, 2=label, 3=optional content INSIDE braces (without braces)
        # Uses a non-greedy match for the props content
        node_pattern = r'\((\w+):(\w+)(?:\s*\{([^}]*)\})?\)'

        result = re.sub(node_pattern, add_tenant_to_node, cypher)

        return result

    async def _generate_cypher(
        self,
        question: str,
        previous_error: str = None,
        previous_cypher: str = None
    ) -> str:
        """
        Use LLM to generate a Cypher query from natural language.

        Args:
            question: Natural language question about the data
            previous_error: Optional error message from a previous failed attempt
            previous_cypher: Optional previous Cypher query that failed

        Returns:
            Generated Cypher query string
        """
        schema = self.graph.get_schema

        # Build the prompt with optional error context for retries
        error_context = ""
        if previous_error and previous_cypher:
            error_context = f"""

## Previous Attempt Failed
The previous query failed with an error. Please fix the issue.

Failed Query:
{previous_cypher}

Error Message:
{previous_error}

Common fixes:
- Check relationship direction syntax: use <-[:REL]- not [:REL]<-
- Ensure node labels and property names match the schema
- Verify relationship types exist in the schema
"""

        prompt = f"""{TEXT_TO_CYPHER_SYSTEM}

## Current Database Schema
{schema}
{error_context}
## Important Rules
- Generate ONLY the Cypher query, no explanations
- Do NOT include user_id or project_id filters - they will be added automatically
- Do NOT use any parameters (like $target, $domain, etc.) - use literal values or no filters
- If the question doesn't specify a target, query ALL matching data
- Always use LIMIT to restrict results

User Question: {question}

Cypher Query:"""

        response = await self.llm.ainvoke(prompt)
        cypher = response.content.strip()

        # Clean up the response - remove markdown code blocks if present
        if cypher.startswith("```"):
            lines = cypher.split("\n")
            cypher = "\n".join(lines[1:-1] if lines[-1] == "```" else lines[1:])

        return cypher.strip()

    def get_tool(self) -> Optional[callable]:
        """
        Set up and return the Neo4j text-to-cypher tool.

        Returns:
            The query_graph tool function, or None if setup fails
        """
        logger.info(f"Setting up Neo4j connection to {self.uri}")

        try:
            self.graph = Neo4jGraph(
                url=self.uri,
                username=self.user,
                password=self.password
            )

            # Store reference to self for use in the tool closure
            manager = self

            @tool
            async def query_graph(question: str) -> str:
                """
                Query the Neo4j graph database using natural language.

                Use this tool to retrieve reconnaissance data such as:
                - Domains, subdomains, and their relationships
                - IP addresses and their associated ports/services
                - Technologies detected on targets
                - Vulnerabilities and CVEs found
                - Any other security reconnaissance data

                This is the PRIMARY source of truth for target information.
                Always query the graph FIRST before using other tools.

                Args:
                    question: Natural language question about the data

                Returns:
                    Query results as a string
                """
                # Get current user/project from context
                user_id = current_user_id.get()
                project_id = current_project_id.get()

                if not user_id or not project_id:
                    return "Error: Missing user_id or project_id context"

                logger.info(f"[{user_id}/{project_id}] Generating Cypher for: {question[:50]}...")

                last_error = None
                last_cypher = None

                for attempt in range(CYPHER_MAX_RETRIES):
                    try:
                        # Step 1: Generate Cypher from natural language (with error context on retry)
                        if attempt == 0:
                            cypher = await manager._generate_cypher(question)
                        else:
                            logger.info(f"[{user_id}/{project_id}] Retry {attempt}/{CYPHER_MAX_RETRIES - 1}: Regenerating Cypher...")
                            cypher = await manager._generate_cypher(
                                question,
                                previous_error=last_error,
                                previous_cypher=last_cypher
                            )

                        logger.info(f"[{user_id}/{project_id}] Generated Cypher (attempt {attempt + 1}): {cypher}")

                        # Step 2: Inject mandatory tenant filters
                        filtered_cypher = manager._inject_tenant_filter(cypher, user_id, project_id)
                        logger.info(f"[{user_id}/{project_id}] Filtered Cypher: {filtered_cypher}")

                        # Step 3: Execute the filtered query
                        result = manager.graph.query(
                            filtered_cypher,
                            params={
                                "tenant_user_id": user_id,
                                "tenant_project_id": project_id
                            }
                        )

                        if not result:
                            return "No results found"

                        return str(result)

                    except Exception as e:
                        error_msg = str(e)
                        logger.warning(f"[{user_id}/{project_id}] Query attempt {attempt + 1} failed: {error_msg}")
                        last_error = error_msg
                        last_cypher = cypher if 'cypher' in locals() else None

                        # If this is the last attempt, return the error
                        if attempt == CYPHER_MAX_RETRIES - 1:
                            logger.error(f"[{user_id}/{project_id}] All {CYPHER_MAX_RETRIES} attempts failed")
                            return f"Error querying graph after {CYPHER_MAX_RETRIES} attempts: {error_msg}"

                return "Error: Unexpected end of retry loop"

            logger.info("Neo4j graph query tool configured with tenant filtering")
            return query_graph

        except Exception as e:
            logger.error(f"Failed to set up Neo4j: {e}")
            logger.warning("Continuing without graph query tool")
            return None


# =============================================================================
# PHASE-AWARE TOOL EXECUTOR
# =============================================================================

class PhaseAwareToolExecutor:
    """
    Executes tools with phase-awareness.
    Validates that tools are allowed in the current phase before execution.
    """

    def __init__(self, mcp_manager: MCPToolsManager, graph_tool: Optional[callable]):
        self.mcp_manager = mcp_manager
        self.graph_tool = graph_tool
        self._all_tools: Dict[str, callable] = {}

        # Register graph tool
        if graph_tool:
            self._all_tools["query_graph"] = graph_tool

    def register_mcp_tools(self, tools: List) -> None:
        """Register MCP tools after they're loaded."""
        for tool in tools:
            tool_name = getattr(tool, 'name', None)
            if tool_name:
                self._all_tools[tool_name] = tool

    def _extract_text_from_output(self, output) -> str:
        """
        Extract clean text from MCP tool output.

        MCP tools return responses in various formats:
        - List of content blocks: [{'type': 'text', 'text': '...', 'id': '...'}]
        - Plain string
        - Other formats

        This method normalizes all formats to clean text.
        """
        if output is None:
            return ""

        # If it's already a string, return it
        if isinstance(output, str):
            return output

        # If it's a list (MCP content blocks format)
        if isinstance(output, list):
            text_parts = []
            for item in output:
                if isinstance(item, dict):
                    # Extract 'text' field from content block
                    if 'text' in item:
                        text_parts.append(item['text'])
                    elif 'content' in item:
                        text_parts.append(str(item['content']))
                elif isinstance(item, str):
                    text_parts.append(item)
            return '\n'.join(text_parts) if text_parts else str(output)

        # If it's a dict with 'text' or 'content'
        if isinstance(output, dict):
            if 'text' in output:
                return output['text']
            if 'content' in output:
                return str(output['content'])
            if 'output' in output:
                return str(output['output'])

        # Fallback: convert to string
        return str(output)

    async def execute(
        self,
        tool_name: str,
        tool_args: dict,
        phase: str
    ) -> dict:
        """
        Execute a tool if allowed in the current phase.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool
            phase: Current agent phase

        Returns:
            dict with 'success', 'output', and optionally 'error'
        """
        # Check phase restriction
        if not is_tool_allowed_in_phase(tool_name, phase):
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' is not allowed in '{phase}' phase. "
                         f"This tool requires: {get_phase_for_tool(tool_name)}"
            }

        # Get the tool
        tool = self._all_tools.get(tool_name)
        if not tool:
            return {
                "success": False,
                "output": None,
                "error": f"Tool '{tool_name}' not found"
            }

        try:
            # Execute the tool
            if tool_name == "query_graph":
                # Graph tool expects 'question' argument
                question = tool_args.get("question", "")
                output = await tool.ainvoke(question)
            else:
                # MCP tools - invoke with the appropriate argument
                output = await tool.ainvoke(tool_args)

            # Extract clean text from MCP response
            # MCP returns list of content blocks: [{'type': 'text', 'text': '...', 'id': '...'}]
            clean_output = self._extract_text_from_output(output)

            return {
                "success": True,
                "output": clean_output,
                "error": None
            }

        except Exception as e:
            logger.error(f"Tool execution failed: {tool_name} - {e}")
            return {
                "success": False,
                "output": None,
                "error": str(e)
            }

    async def execute_with_progress(
        self,
        tool_name: str,
        tool_args: dict,
        phase: str,
        progress_callback: Callable[[str, str, bool], Awaitable[None]],
        poll_interval: float = 5.0
    ) -> dict:
        """
        Execute metasploit_console with integrated progress streaming.

        Polls the HTTP progress endpoint during execution and sends updates
        via the progress_callback.

        Args:
            tool_name: Name of the tool to execute
            tool_args: Arguments for the tool
            phase: Current agent phase
            progress_callback: Async callback(tool_name, chunk, is_final)
            poll_interval: How often to poll for progress (seconds)

        Returns:
            dict with 'success', 'output', and optionally 'error'
        """
        # Start the main tool execution as a background task
        execution_task = asyncio.create_task(
            self.execute(tool_name, tool_args, phase)
        )

        last_line_count = 0
        last_output = ""

        async with httpx.AsyncClient(timeout=2.0) as client:
            while not execution_task.done():
                await asyncio.sleep(poll_interval)

                if execution_task.done():
                    break

                try:
                    resp = await client.get(MCP_METASPLOIT_PROGRESS_URL)
                    if resp.status_code == 200:
                        progress = resp.json()

                        if progress.get("active"):
                            current_output = progress.get("output", "")
                            line_count = progress.get("line_count", 0)
                            elapsed = progress.get("elapsed_seconds", 0)

                            # Only send if new content
                            if line_count > last_line_count and current_output != last_output:
                                # Calculate the new portion
                                if last_output and current_output.startswith(last_output):
                                    new_content = current_output[len(last_output):]
                                else:
                                    new_content = current_output

                                if new_content.strip():
                                    # Format progress update with context
                                    progress_msg = f"[Progress: {line_count} lines, {elapsed}s]\n{new_content[-1000:]}"
                                    await progress_callback(
                                        tool_name,
                                        progress_msg,
                                        False  # not final
                                    )

                                last_output = current_output
                                last_line_count = line_count

                except httpx.TimeoutException:
                    # Progress polling timeout is fine, continue
                    pass
                except httpx.HTTPError as e:
                    # Connection errors during polling are best-effort, log and continue
                    logger.debug(f"Progress polling error (non-fatal): {e}")
                except Exception as e:
                    # Unexpected errors, log but don't fail the execution
                    logger.warning(f"Progress polling unexpected error: {e}")

        # Wait for the execution to complete and return result
        return await execution_task

    def get_all_tools(self) -> List:
        """Get all registered tools."""
        return list(self._all_tools.values())

    def get_tools_for_phase(self, phase: str) -> List:
        """Get tools allowed in the given phase."""
        return [
            tool for name, tool in self._all_tools.items()
            if is_tool_allowed_in_phase(name, phase)
        ]


def get_phase_for_tool(tool_name: str) -> str:
    """Get the minimum phase required for a tool."""
    from params import TOOL_PHASE_MAP
    allowed_phases = TOOL_PHASE_MAP.get(tool_name, [])
    if "informational" in allowed_phases:
        return "informational"
    elif "exploitation" in allowed_phases:
        return "exploitation"
    elif "post_exploitation" in allowed_phases:
        return "post_exploitation"
    return "unknown"
