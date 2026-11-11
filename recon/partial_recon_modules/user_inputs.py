import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _resolve_hostname, attach_org, root_for_host, scope_roots


def _create_user_subdomains_in_graph(domain, subdomains: list, user_id: str, project_id: str) -> None:
    """Create Subdomain nodes in the graph for user-provided subdomains (MERGE, no duplicates).

    `domain` is one root, or the run's roots (a list): each subdomain then
    attaches to the root it sits under, so a batch does not hang every host off
    the first root's Domain.
    """
    from graph_db import Neo4jClient
    roots = scope_roots({"domains": domain}) if isinstance(domain, list) else [domain]
    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            return
        driver = graph_client.driver
        with driver.session() as session:
            for sub in subdomains:
                root = root_for_host(sub, roots) or roots[0]
                # Resolve the subdomain to get IPs
                ips = _resolve_hostname(sub)
                # Create Subdomain node attached to its root's Domain
                session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid}) WHERE toLower(d.name) = toLower($domain)
                    MERGE (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                    ON CREATE SET s.source = 'partial_recon_user_input',
                                  s.updated_at = datetime()
                    MERGE (s)-[:BELONGS_TO]->(d)
                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                    """,
                    domain=attach_org(root), sub=sub, uid=user_id, pid=project_id,
                )
                # Create IP nodes and RESOLVES_TO relationships
                for bucket in ("ipv4", "ipv6"):
                    for addr in ips.get(bucket, []):
                        session.run(
                            """
                            MERGE (i:IP {address: $addr, user_id: $uid, project_id: $pid})
                            ON CREATE SET i.version = $version,
                                          i.source = 'partial_recon_user_input',
                                          i.updated_at = datetime()
                            WITH i
                            MATCH (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                            MERGE (s)-[:RESOLVES_TO]->(i)
                            """,
                            addr=addr, uid=user_id, pid=project_id,
                            version=bucket, sub=sub,
                        )
            if subdomains:
                print(f"[+][Partial Recon] Created/merged {len(subdomains)} user subdomain nodes in graph")


# Set by update_user_input_status after the run wrote the node's edges, so a
# node in one of these states will get no further edge.
_FINISHED_STATUSES = ("completed", "error")


def _orphans_no_run_will_link(orphans, own_ids) -> list:
    """The ids of the orphan UserInputs no live run can still link: this run's
    own, and those whose run has finished. A 'running' node another run made
    may be waiting for that run's results (httpx makes its node before it
    scans), and a node with no status comes from a writer that never sets one,
    so neither is this run's to judge."""
    return sorted(row["id"] for row in orphans
                  if row["id"] in own_ids or row.get("status") in _FINISHED_STATUSES)


def _cleanup_orphan_user_inputs(user_id: str, project_id: str) -> int:
    """
    Delete UserInput nodes that have no outgoing relationships (except
    the incoming HAS_USER_INPUT from Domain).

    After a partial recon tool runs, a UserInput node may have been created
    for user-provided targets (generic IPs, URLs, etc.). If the scan produced
    no results for those targets, the UserInput sits orphaned -- connected to
    the Domain via HAS_USER_INPUT but with no outgoing children.

    Different tools create different outgoing relationships from UserInput:
      - PRODUCED (port scanners, resource enum tools)
      - HAS_VULNERABILITY (Nuclei via BaseURL)
      - etc.

    Up to twelve partial runs of a project run at once, so only the orphans
    _orphans_no_run_will_link names are deleted, and the delete re-checks the
    missing edge in case a run linked its node since the read.

    Returns:
        Number of orphan UserInput nodes deleted.
    """
    try:
        from graph_db import Neo4jClient
        from graph_db.mixins.recon.user_input_mixin import user_inputs_created_this_run
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return 0
            with graph_client.driver.session() as session:
                orphans = [dict(row) for row in session.run(
                    """
                    MATCH (ui:UserInput {user_id: $uid, project_id: $pid})
                    WHERE NOT (ui)-->()
                    RETURN ui.id AS id, ui.status AS status
                    """,
                    uid=user_id, pid=project_id,
                )]
                ids = _orphans_no_run_will_link(orphans, user_inputs_created_this_run())
                if not ids:
                    return 0
                result = session.run(
                    """
                    MATCH (ui:UserInput {user_id: $uid, project_id: $pid})
                    WHERE ui.id IN $ids AND NOT (ui)-->()
                    WITH ui, ui.id AS uid_id
                    DETACH DELETE ui
                    RETURN count(uid_id) AS deleted
                    """,
                    uid=user_id, pid=project_id, ids=ids,
                )
                record = result.single()
                deleted = record["deleted"] if record else 0
                if deleted:
                    print(f"[+][Partial Recon] Cleaned up {deleted} orphan UserInput node(s) (no outgoing relationships)")
                return deleted
    except Exception as e:
        print(f"[!][Partial Recon] UserInput cleanup failed: {e}")
        return 0
