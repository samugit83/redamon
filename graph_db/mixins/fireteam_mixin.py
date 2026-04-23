"""Neo4j query helpers for Fireteam (multi-agent) post-mortem.

Assumes ChainStep / ChainFinding nodes have been written with the
``fireteam_id``, ``agent_id``, ``source_agent`` properties populated by
the orchestrator's chain_graph_writer. Pair with the ``idx_chainstep_by_fireteam``
/ ``idx_chainfinding_by_fireteam`` indexes defined in ``graph_db/schema.py``.
"""

from typing import List, Optional


class FireteamMixin:
    """Mixin adding fireteam post-mortem queries to Neo4jClient.

    Mix into a Neo4jClient that exposes a ``session()`` context manager or
    ``driver`` attribute, following the existing mixin conventions.
    """

    # ----- Wave-level -----

    def list_fireteams_for_project(
        self,
        *,
        user_id: str,
        project_id: str,
        limit: int = 100,
    ) -> List[dict]:
        """Return distinct (fireteam_id, started_at, member_count) for the project."""
        query = """
        MATCH (s:ChainStep {user_id: $user_id, project_id: $project_id})
        WHERE s.fireteam_id IS NOT NULL
        WITH s.fireteam_id AS fireteam_id,
             min(s.created_at) AS started_at,
             collect(DISTINCT s.agent_id) AS members
        RETURN fireteam_id, started_at, size(members) AS member_count, members
        ORDER BY started_at DESC
        LIMIT $limit
        """
        with self.driver.session() as session:
            rows = session.run(query, user_id=user_id, project_id=project_id, limit=limit)
            return [
                {
                    "fireteam_id": r["fireteam_id"],
                    "started_at": r["started_at"],
                    "member_count": r["member_count"],
                    "members": r["members"],
                }
                for r in rows
            ]

    def get_fireteam_steps(
        self,
        *,
        user_id: str,
        project_id: str,
        fireteam_id: str,
    ) -> List[dict]:
        """Return every ChainStep written by members of the given fireteam,
        ordered chronologically. Useful for timeline reconstruction."""
        query = """
        MATCH (s:ChainStep {user_id: $user_id, project_id: $project_id, fireteam_id: $fireteam_id})
        RETURN s.step_id AS step_id, s.agent_id AS agent_id, s.agent_name AS agent_name,
               s.iteration AS iteration, s.phase AS phase,
               s.tool_name AS tool_name, s.tool_args_summary AS tool_args_summary,
               s.success AS success, s.error_message AS error_message,
               s.created_at AS created_at
        ORDER BY s.created_at
        """
        with self.driver.session() as session:
            rows = session.run(
                query, user_id=user_id, project_id=project_id, fireteam_id=fireteam_id
            )
            return [dict(r) for r in rows]

    # ----- Finding-level -----

    def get_fireteam_findings(
        self,
        *,
        user_id: str,
        project_id: str,
        fireteam_id: Optional[str] = None,
    ) -> List[dict]:
        """Return all ChainFinding rows attributed to a fireteam (or any
        fireteam when ``fireteam_id`` is None)."""
        if fireteam_id:
            query = """
            MATCH (f:ChainFinding {user_id: $user_id, project_id: $project_id, fireteam_id: $fireteam_id})
            RETURN f.finding_id AS finding_id, f.source_agent AS source_agent,
                   f.agent_id AS agent_id, f.severity AS severity,
                   f.finding_type AS finding_type, f.title AS title,
                   f.evidence AS evidence, f.confidence AS confidence,
                   f.phase AS phase, f.created_at AS created_at
            ORDER BY f.severity DESC, f.created_at
            """
            params = {"user_id": user_id, "project_id": project_id, "fireteam_id": fireteam_id}
        else:
            query = """
            MATCH (f:ChainFinding {user_id: $user_id, project_id: $project_id})
            WHERE f.fireteam_id IS NOT NULL
            RETURN f.fireteam_id AS fireteam_id, f.finding_id AS finding_id,
                   f.source_agent AS source_agent, f.agent_id AS agent_id,
                   f.severity AS severity, f.finding_type AS finding_type,
                   f.title AS title, f.evidence AS evidence,
                   f.confidence AS confidence, f.phase AS phase,
                   f.created_at AS created_at
            ORDER BY f.created_at DESC
            """
            params = {"user_id": user_id, "project_id": project_id}

        with self.driver.session() as session:
            rows = session.run(query, **params)
            return [dict(r) for r in rows]

    def count_findings_by_member(
        self,
        *,
        user_id: str,
        project_id: str,
        fireteam_id: str,
    ) -> List[dict]:
        """Aggregate counts per source_agent for the given fireteam. Primary
        driver of the Multi-Agent report section's per-member findingsCount."""
        query = """
        MATCH (f:ChainFinding {user_id: $user_id, project_id: $project_id, fireteam_id: $fireteam_id})
        RETURN f.source_agent AS source_agent, count(f) AS n_findings,
               collect(DISTINCT f.severity) AS severities
        ORDER BY n_findings DESC
        """
        with self.driver.session() as session:
            rows = session.run(
                query, user_id=user_id, project_id=project_id, fireteam_id=fireteam_id
            )
            return [
                {
                    "source_agent": r["source_agent"],
                    "n_findings": r["n_findings"],
                    "severities": r["severities"],
                }
                for r in rows
            ]
