"""The triage run's only graph access.

There are no LLM TOOLS here any more. Triage used to bind `query_graph` and
`web_search` into a ReAct loop, which meant a model steered by scanner output
could write its own Cypher and its own search queries. Steps A to D now read
the graph through the fixed queries in `fact_queries.py`, and the review and
prose calls bind no tools at all, so an injected instruction has nothing to
reach for.

`run_query` survives for the guarded path that is still exercised by the
security tests: anything model-written goes through `scope_query` first.
"""

import logging
import os

from neo4j import READ_ACCESS, AsyncGraphDatabase

from graph_db.tenant_filter import (
    TenantScopeError,
    find_disallowed_write_operation,
    scope_query,
)

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

    async def _execute(self, cypher: str, params: dict) -> list[dict]:
        """Run already-vetted Cypher in a read session.

        Read access mode is belt-and-braces: the write clauses are refused
        before we get here, and a read session makes a missed one fail at the
        server instead of mutating the graph.
        """
        if not self.driver:
            await self.connect()

        async with self.driver.session(default_access_mode=READ_ACCESS) as session:
            result = await session.run(cypher, params)
            return await result.data()

    async def run_query(self, cypher: str, params: dict = None) -> list[dict]:
        """Run LLM-written Cypher, refusing anything that cannot be proven scoped.

        This is the only path the model can reach. It mirrors the main agent's
        `query_graph` chokepoint (`agentic/tools.py`): refuse writes, then
        `scope_query`, which injects the tenant filter, rejects the reserved
        `Muted` label and raises rather than running an unscopable pattern.
        """
        disallowed = find_disallowed_write_operation(cypher)
        if disallowed:
            raise TenantScopeError(
                f"Write operations are not allowed in triage queries "
                f"(found: {disallowed.strip()})"
            )

        scoped = scope_query(cypher, self.user_id, self.project_id)

        query_params = {
            "userId": self.user_id,
            "projectId": self.project_id,
            "tenant_user_id": self.user_id,
            "tenant_project_id": self.project_id,
            **(params or {}),
        }
        return await self._execute(scoped, query_params)

    async def run_static_query(self, cypher: str) -> list[dict]:
        """Run a repo-authored collection query (already carries $userId/$projectId).

        Deliberately separate from `run_query`: these queries are written in
        `prompts/cypher_queries.py`, hand-write their own `NOT x:Muted` terms and
        would not survive `scope_query`'s label requirement. Nothing the model
        emits may reach this method.
        """
        return await self._execute(
            cypher, {"userId": self.user_id, "projectId": self.project_id}
        )
