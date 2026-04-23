import os
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from recon.partial_recon_modules.helpers import _resolve_hostname


def _create_user_subdomains_in_graph(domain: str, subdomains: list, user_id: str, project_id: str) -> None:
    """Create Subdomain nodes in the graph for user-provided subdomains (MERGE, no duplicates)."""
    from graph_db import Neo4jClient
    with Neo4jClient() as graph_client:
        if not graph_client.verify_connection():
            return
        driver = graph_client.driver
        with driver.session() as session:
            for sub in subdomains:
                # Resolve the subdomain to get IPs
                ips = _resolve_hostname(sub)
                # Create Subdomain node attached to Domain
                session.run(
                    """
                    MATCH (d:Domain {name: $domain, user_id: $uid, project_id: $pid})
                    MERGE (s:Subdomain {name: $sub, user_id: $uid, project_id: $pid})
                    ON CREATE SET s.source = 'partial_recon_user_input',
                                  s.updated_at = datetime()
                    MERGE (d)-[:HAS_SUBDOMAIN]->(s)
                    """,
                    domain=domain, sub=sub, uid=user_id, pid=project_id,
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

    This function checks for ANY outgoing relationship from UserInput.
    If the node only has the incoming HAS_USER_INPUT and nothing going out,
    it's an orphan and gets deleted.

    Returns:
        Number of orphan UserInput nodes deleted.
    """
    try:
        from graph_db import Neo4jClient
        with Neo4jClient() as graph_client:
            if not graph_client.verify_connection():
                return 0
            with graph_client.driver.session() as session:
                result = session.run(
                    """
                    MATCH (ui:UserInput {user_id: $uid, project_id: $pid})
                    WHERE NOT (ui)-->()
                    WITH ui, ui.id AS uid_id
                    DETACH DELETE ui
                    RETURN count(uid_id) AS deleted
                    """,
                    uid=user_id, pid=project_id,
                )
                record = result.single()
                deleted = record["deleted"] if record else 0
                if deleted:
                    print(f"[+][Partial Recon] Cleaned up {deleted} orphan UserInput node(s) (no outgoing relationships)")
                return deleted
    except Exception as e:
        print(f"[!][Partial Recon] UserInput cleanup failed: {e}")
        return 0
