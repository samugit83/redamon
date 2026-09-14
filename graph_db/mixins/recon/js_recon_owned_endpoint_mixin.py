"""JS recon endpoint ownership guard.

JS recon can extract endpoint-looking URLs from client-side code whose base URL
is guessed, external, or otherwise not part of the project's discovered attack
surface. Those candidates are useful evidence, but they must not become
first-party Endpoint inventory unless a tenant-scoped BaseURL already exists.

This wrapper keeps JsReconMixin's public behaviour while enforcing that graph
invariant after ingestion:

* normal network Endpoint nodes written by JS recon must match an existing
  BaseURL in the same tenant/project;
* valid JS-recon Endpoints are structurally owned by that BaseURL through
  HAS_ENDPOINT;
* uploaded JS keeps the existing ``baseurl='upload'`` exception.
"""

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin


class JsReconOwnedEndpointMixin(JsReconMixin):
    """Add BaseURL ownership/inventory integrity to JS recon ingestion."""

    def update_graph_from_js_recon(
        self,
        recon_data: dict,
        user_id: str,
        project_id: str,
    ) -> dict:
        stats = super().update_graph_from_js_recon(recon_data, user_id, project_id)
        if not isinstance(stats, dict) or stats.get("status") == "skipped":
            return stats

        with self.driver.session() as session:
            # Remove only Endpoint nodes whose canonical source is JS recon and
            # whose claimed network BaseURL does not exist in this project.
            # DETACH also removes the JS-file evidence link to the invalid
            # inventory node; the originating JsReconFinding remains intact.
            removed = session.run(
                """
                MATCH (e:Endpoint {user_id: $uid, project_id: $pid})
                WHERE e.source = 'js_recon'
                  AND coalesce(e.baseurl, '') <> 'upload'
                  AND NOT EXISTS {
                    MATCH (:BaseURL {
                        url: e.baseurl,
                        user_id: $uid,
                        project_id: $pid
                    })
                  }
                WITH collect(e) AS doomed
                FOREACH (e IN doomed | DETACH DELETE e)
                RETURN size(doomed) AS removed
                """,
                uid=user_id,
                pid=project_id,
            ).single()

            # Every remaining network JS endpoint has a concrete BaseURL owner.
            linked = session.run(
                """
                MATCH (e:Endpoint {
                    user_id: $uid,
                    project_id: $pid,
                    source: 'js_recon'
                })
                WHERE coalesce(e.baseurl, '') <> 'upload'
                MATCH (bu:BaseURL {
                    url: e.baseurl,
                    user_id: $uid,
                    project_id: $pid
                })
                MERGE (bu)-[r:HAS_ENDPOINT]->(e)
                RETURN count(r) AS linked
                """,
                uid=user_id,
                pid=project_id,
            ).single()

        removed_count = int((removed or {}).get("removed", 0) or 0)
        linked_count = int((linked or {}).get("linked", 0) or 0)
        stats["invalid_endpoints_removed"] = removed_count
        stats["endpoint_owners_linked"] = linked_count

        # ``endpoints_created`` is a final-state count from the caller's point
        # of view. Do not report nodes that this integrity guard discarded.
        if "endpoints_created" in stats:
            stats["endpoints_created"] = max(
                0, int(stats.get("endpoints_created", 0) or 0) - removed_count
            )

        return stats
