"""DNS resolution relationship integrity guard.

Some recon writers historically included relationship properties in the
``MERGE`` identity for ``RESOLVES_TO`` while other writers created the same
Subdomain -> IP edge without those properties. Neo4j then permits parallel
relationships between the same two nodes.

This mixin runs after domain/IP discovery and collapses those parallel edges
inside the current tenant/project. ``record_type`` remains metadata on the
canonical relationship rather than part of its graph identity.
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

    def _dedupe_resolution_edges(
        self,
        user_id: str,
        project_id: str,
        stats: dict | None = None,
    ) -> int:
        with self.driver.session() as session:
            row = session.run(
                """
                MATCH (s:Subdomain {user_id: $uid, project_id: $pid})
                      -[r:RESOLVES_TO]->
                      (i:IP {user_id: $uid, project_id: $pid})
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
                """,
                uid=user_id,
                pid=project_id,
            ).single()

        removed = int((row or {}).get("removed", 0) or 0)
        if isinstance(stats, dict):
            stats["duplicate_resolution_edges_removed"] = removed
        return removed
