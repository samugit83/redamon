"""Tools available to the triage agent during ReAct analysis phase."""

import logging
import os

from neo4j import AsyncGraphDatabase

logger = logging.getLogger(__name__)

NEO4J_URI = os.environ.get("NEO4J_URI", "bolt://neo4j:7687")
NEO4J_USER = os.environ.get("NEO4J_USER", "neo4j")
NEO4J_PASSWORD = os.environ.get("NEO4J_PASSWORD", "redamon_neo4j")


class TriageNeo4jToolManager:
    """Manages Neo4j connections and query execution for triage agent."""

    def __init__(self, user_id: str, project_id: str):
        self.user_id = user_id
        self.project_id = project_id
        self.driver = None

    async def connect(self):
        self.driver = AsyncGraphDatabase.driver(
            NEO4J_URI, auth=(NEO4J_USER, NEO4J_PASSWORD)
        )

    async def close(self):
        if self.driver:
            await self.driver.close()

    async def run_query(self, cypher: str, params: dict = None) -> list[dict]:
        """Run a Cypher query with tenant filtering injected."""
        if not self.driver:
            await self.connect()

        query_params = {
            "userId": self.user_id,
            "projectId": self.project_id,
            **(params or {}),
        }

        async with self.driver.session() as session:
            result = await session.run(cypher, query_params)
            records = await result.data()
            return records

    async def run_static_query(self, cypher: str) -> list[dict]:
        """Run a static collection query (already has $userId/$projectId params)."""
        return await self.run_query(cypher)


class TriageWebSearchManager:
    """Web search tool for enriching triage analysis."""

    def __init__(self, tavily_api_key: str = "", key_rotator=None):
        self.tavily_api_key = tavily_api_key or ""
        self.key_rotator = key_rotator  # Optional[KeyRotator]

    async def search(self, query: str, max_results: int = 5) -> str:
        """Search the web using Tavily API."""
        api_key = self.key_rotator.current_key if self.key_rotator and self.key_rotator.has_keys else self.tavily_api_key
        if not api_key:
            return "Web search unavailable: Tavily API key not configured in Global Settings"

        try:
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.tavily.com/search",
                    json={
                        "api_key": api_key,
                        "query": query,
                        "max_results": max_results,
                        "search_depth": "basic",
                    },
                )
                resp.raise_for_status()
                data = resp.json()
                if self.key_rotator:
                    self.key_rotator.tick()

                results = []
                for r in data.get("results", []):
                    results.append(
                        f"**{r['title']}**\n{r['url']}\n{r.get('content', '')[:500]}"
                    )
                return "\n\n---\n\n".join(results) if results else "No results found."
        except Exception as e:
            logger.error(f"Web search failed: {e}")
            return f"Web search error: {e}"


# Tool definitions for the LLM
TRIAGE_TOOLS = [
    {
        "name": "query_graph",
        "description": (
            "Run a follow-up Cypher query against the Neo4j graph database. "
            "Use this when you need additional context about specific findings. "
            "The query must use $userId and $projectId parameters for tenant filtering."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "cypher": {
                    "type": "string",
                    "description": "Cypher query to execute. Must include {user_id: $userId, project_id: $projectId} filters.",
                },
            },
            "required": ["cypher"],
        },
    },
    {
        "name": "web_search",
        "description": (
            "Search the web for vulnerability details, CVE information, "
            "CISA KEV catalog status, or exploit availability."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "query": {
                    "type": "string",
                    "description": "Search query",
                },
            },
            "required": ["query"],
        },
    },
]
