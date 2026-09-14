"""DNS resolution relationship integrity guard.

Some graph writers historically included relationship properties in the
``MERGE`` identity for ``RESOLVES_TO`` while other writers created the same
Subdomain -> IP edge without those properties. Neo4j then permits parallel
relationships between the same two nodes.

The project-scoped hooks below clean up immediately after the main discovery
writers, while the lifecycle sweep catches every other writer before a graph
client closes. ``record_type`` remains metadata on the canonical relationship
rather than part of its graph identity.
"""


class ResolutionIntegrityMixin:
    """Normalize ``RESOLVES_TO`` to one edge per Subdomain/IP pair."""

    def update_graph_from_domain_discovery(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        stats = super().update_graph_from_domain_discovery(
            recon_data, user_id, project_id
        )
        self._dedupe_resolution_edges(user_id, project_id, stats)
        return stats

    def update_graph_from_ip_recon(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        stats = super().update_graph_from_ip_recon(
            recon_data, user_id, project_id
        )
        self._dedupe_resolution_edges(user_id, project_id, stats)
        return stats

    def update_graph_from_partial_discovery(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
        user_input_id: str | None = None,
    ) -> dict:
        """Apply the same invariant to partial/user-input discovery writes."""
        stats = super().update_graph_from_partial_discovery(
            recon_data, user_id, project_id, user_input_id
        )
        self._dedupe_resolution_edges(user_id, project_id, stats)
        return stats

    @staticmethod
    def _dedupe_query(project_scoped: bool) -> str:
        scope = (
            "MATCH (s:Subdomain {user_id: $uid, project_id: $pid})\n"
            "      -[r:RESOLVES_TO]->\n"
            "      (i:IP {user_id: $uid, project_id: $pid})"
            if project_scoped
            else
            "MATCH (s:Subdomain)-[r:RESOLVES_TO]->(i:IP)\n"
            "WHERE s.user_id IS NOT NULL\n"
            "  AND s.project_id IS NOT NULL\n"
            "  AND i.user_id = s.user_id\n"
            "  AND i.project_id = s.project_id"
        )
        return f"""
                {scope}
                WITH s, i, collect(r) AS rels
                WHERE size(rels) > 1
                WITH rels,
                     head(rels) AS keep,
                     tail(rels) AS extras,
                     head([x IN rels WHERE x.record_type IS NOT NULL |
                           x.record_type]) AS discovered_record_type
                SET keep.record_type = coalesce(
                    keep.record_type,
                    discovered_record_type
                )
                FOREACH (x IN extras | DELETE x)
                RETURN coalesce(sum(size(extras)), 0) AS removed
                """

    def _dedupe_resolution_edges(
        self,
        user_id: str,
        project_id: str,
        stats: dict | None = None,
    ) -> int:
        """Collapse duplicate resolution edges inside one tenant/project."""
        with self.driver.session() as session:
            row = session.run(
                self._dedupe_query(project_scoped=True),
                uid=user_id,
                pid=project_id,
            ).single()

        removed = int((row or {}).get("removed", 0) or 0)
        if isinstance(stats, dict):
            stats["duplicate_resolution_edges_removed"] = removed
        return removed

    def _dedupe_all_resolution_edges(self) -> int:
        """Final lifecycle guard for writers outside the main recon mixins.

        Some partial-recon helpers write directly through ``client.driver`` and
        therefore cannot be intercepted by an ``update_graph_*`` wrapper.  A
        final sweep on client close makes the invariant apply to those writers
        too while still refusing to cross tenant/project boundaries.
        """
        with self.driver.session() as session:
            row = session.run(
                self._dedupe_query(project_scoped=False)
            ).single()
        return int((row or {}).get("removed", 0) or 0)
