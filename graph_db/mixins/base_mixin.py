"""
BaseMixin: Neo4j connection lifecycle and project-level data cleanup.

Provides:
- Driver initialization and context manager support
- Schema initialization (called once at startup)
- clear_project_data: wipe all data for a project
- clear_gvm_data: selective GVM data cleanup
"""

import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

from neo4j import GraphDatabase
from dotenv import load_dotenv

from graph_db.schema import init_schema

# Load environment variables from local .env file
load_dotenv(Path(__file__).parent.parent / ".env")


class BaseMixin:
    _SEEN_TIMESTAMP_BATCH_SIZE = 1000

    def __init__(self, uri=None, user=None, password=None):
        self.uri = uri or os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = user or os.getenv("NEO4J_USER")
        self.password = password or os.getenv("NEO4J_PASSWORD")
        self._init_recon_job_context()
        self.driver = GraphDatabase.driver(self.uri, auth=(self.user, self.password))
        with self.driver.session() as session:
            init_schema(session)

    def _init_recon_job_context(self):
        self.recon_job_started_at = os.getenv("RECON_JOB_STARTED_AT")
        if self.recon_job_started_at:
            try:
                started_at = datetime.fromisoformat(
                    self.recon_job_started_at.replace("Z", "+00:00")
                )
            except ValueError as exc:
                raise ValueError(
                    "RECON_JOB_STARTED_AT must be a valid ISO-8601 timestamp"
                ) from exc

            if started_at.tzinfo is None or started_at.utcoffset() is None:
                raise ValueError(
                    "RECON_JOB_STARTED_AT must include timezone information"
                )

            self.recon_job_started_at = (
                started_at.astimezone(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )
        else:
            self.recon_job_started_at = (
                datetime.now(timezone.utc)
                .replace(microsecond=0)
                .isoformat()
                .replace("+00:00", "Z")
            )

        self.recon_job_id = os.getenv("RECON_JOB_ID")
        if not self.recon_job_id:
            stamp = self.recon_job_started_at.replace("-", "").replace(":", "")
            stamp = stamp.replace("+0000", "Z").replace(".", "")
            self.recon_job_id = f"adhoc-{stamp[:16]}-{uuid.uuid4().hex[:8]}"

    def _recon_job_params(self) -> dict[str, str]:
        return {
            "recon_job_id": self.recon_job_id,
            "recon_job_started_at": self.recon_job_started_at,
        }

    def _node_seen_set_clause(self, alias: str) -> str:
        return (
            f"{alias}.first_seen = coalesce({alias}.first_seen, datetime($recon_job_started_at)), "
            f"{alias}.first_seen_job_id = coalesce({alias}.first_seen_job_id, $recon_job_id), "
            f"{alias}.last_seen = datetime($recon_job_started_at), "
            f"{alias}.last_seen_job_id = $recon_job_id"
        )

    def close(self):
        self.driver.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()

    def verify_connection(self):
        """Verify the connection to Neo4j is working."""
        try:
            with self.driver.session() as session:
                result = session.run("RETURN 1 AS test")
                return result.single()["test"] == 1
        except Exception as e:
            print(f"[!][graph-db] Neo4j connection failed: {e}")
            return False

    def normalize_recon_seen_timestamps(self) -> dict[str, int]:
        """Convert project-scoped legacy string seen timestamps to datetimes."""
        stats = {
            "first_seen_converted": 0,
            "last_seen_converted": 0,
            "malformed_first_seen": 0,
            "malformed_last_seen": 0,
        }

        with self.driver.session() as session:
            for property_name in ("first_seen", "last_seen"):
                converted, malformed = self._normalize_recon_seen_property(
                    session, property_name
                )
                stats[f"{property_name}_converted"] = converted
                stats[f"malformed_{property_name}"] = malformed

        return stats

    def _normalize_recon_seen_property(self, session, property_name: str):
        after_element_id = None
        converted = 0
        malformed = 0

        while True:
            records = list(
                session.run(
                    f"""
                    MATCH (n)
                    WHERE n.project_id IS NOT NULL
                      AND n.{property_name} IS :: STRING NOT NULL
                      AND (
                          $after_element_id IS NULL
                          OR elementId(n) > $after_element_id
                      )
                    RETURN elementId(n) AS element_id,
                           n.{property_name} AS value
                    ORDER BY element_id
                    LIMIT $batch_size
                    """,
                    after_element_id=after_element_id,
                    batch_size=self._SEEN_TIMESTAMP_BATCH_SIZE,
                )
            )
            if not records:
                break

            update_rows = []
            for record in records:
                value = record["value"]
                try:
                    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    malformed += 1
                    continue

                if parsed.tzinfo is None or parsed.utcoffset() is None:
                    malformed += 1
                    continue

                update_rows.append(
                    {
                        "element_id": record["element_id"],
                        "value": parsed.astimezone(timezone.utc).isoformat(),
                    }
                )

            if update_rows:
                result = session.run(
                    f"""
                    UNWIND $rows AS row
                    MATCH (n)
                    WHERE elementId(n) = row.element_id
                      AND n.project_id IS NOT NULL
                      AND n.{property_name} IS :: STRING NOT NULL
                    SET n.{property_name} = datetime(row.value)
                    RETURN count(n) AS converted
                    """,
                    rows=update_rows,
                )
                record = result.single()
                if record:
                    converted += record["converted"]

            after_element_id = records[-1]["element_id"]

        return converted, malformed

    def clear_project_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete all nodes and relationships for a specific project.

        This should be called before re-running a recon scan to ensure
        old data is removed and replaced with fresh results.

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted nodes and relationships
        """
        stats = {"nodes_deleted": 0, "relationships_deleted": 0}

        with self.driver.session() as session:
            # Delete all nodes and relationships for this project
            # DETACH DELETE removes the node and all its relationships
            result = session.run(
                """
                MATCH (n)
                WHERE n.user_id = $user_id AND n.project_id = $project_id
                DETACH DELETE n
                RETURN count(n) as deleted_count
                """,
                user_id=user_id, project_id=project_id
            )
            record = result.single()
            if record:
                stats["nodes_deleted"] = record["deleted_count"]

            print(f"[*][graph-db] Cleared project data: {stats['nodes_deleted']} nodes deleted")

        return stats

    def clear_gvm_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GVM-specific nodes and relationships for a project.

        Preserves all recon data (Domain, Subdomain, IP, Port, BaseURL,
        Endpoint, Parameter, Service, etc.). Only removes:
        - Vulnerability nodes with source='gvm'
        - GVM-only CVE nodes (not shared with recon)
        - GVM-only Technology nodes (detected_by='gvm')
        - GVM enrichments on shared Technology nodes (CPE data)
        - USES_TECHNOLOGY relationships with detected_by='gvm'
        - Domain node GVM metadata properties

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted/cleaned items
        """
        stats = {
            "vulnerabilities_deleted": 0,
            "cves_deleted": 0,
            "technologies_deleted": 0,
            "technologies_cleaned": 0,
            "traceroutes_deleted": 0,
            "certificates_deleted": 0,
            "exploits_gvm_deleted": 0,
            "relationships_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete GVM Vulnerability nodes (and all their relationships)
            result = session.run(
                """
                MATCH (v:Vulnerability {user_id: $uid, project_id: $pid})
                WHERE v.source = 'gvm'
                DETACH DELETE v
                RETURN count(v) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["vulnerabilities_deleted"] = record["deleted"]

            # 1b. Delete Traceroute nodes
            result = session.run(
                """
                MATCH (tr:Traceroute {user_id: $uid, project_id: $pid})
                DETACH DELETE tr
                RETURN count(tr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["traceroutes_deleted"] = record["deleted"]

            # 1c. Delete GVM-sourced Certificate nodes (preserve recon/httpx certificates)
            result = session.run(
                """
                MATCH (c:Certificate {user_id: $uid, project_id: $pid})
                WHERE c.source = 'gvm'
                DETACH DELETE c
                RETURN count(c) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["certificates_deleted"] = record["deleted"]

            # 1d. Delete ExploitGvm nodes
            result = session.run(
                """
                MATCH (e:ExploitGvm {user_id: $uid, project_id: $pid})
                DETACH DELETE e
                RETURN count(e) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["exploits_gvm_deleted"] = record["deleted"]

            # 2. Delete GVM-only CVE nodes (created by ExploitGvm, not linked to non-GVM sources)
            result = session.run(
                """
                MATCH (c:CVE {user_id: $uid, project_id: $pid, source: 'gvm'})
                DETACH DELETE c
                RETURN count(c) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["cves_deleted"] = record["deleted"]

            # 3. Delete GVM-only Technology nodes (detected_by exactly 'gvm')
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by = 'gvm'
                DETACH DELETE t
                RETURN count(t) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_deleted"] = record["deleted"]

            # 4. Clean shared Technology nodes (strip GVM enrichment)
            result = session.run(
                """
                MATCH (t:Technology {user_id: $uid, project_id: $pid})
                WHERE t.detected_by CONTAINS ',gvm'
                SET t.detected_by = replace(t.detected_by, ',gvm', ''),
                    t.cpe = null, t.cpe_vendor = null, t.cpe_product = null
                RETURN count(t) as cleaned
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["technologies_cleaned"] = record["cleaned"]

            # 5. Delete GVM USES_TECHNOLOGY relationships (Port→Tech and IP→Tech)
            result = session.run(
                """
                MATCH ({user_id: $uid, project_id: $pid})-[r:USES_TECHNOLOGY]->()
                WHERE r.detected_by = 'gvm'
                DELETE r
                RETURN count(r) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["relationships_deleted"] = record["deleted"]

            # 6. Clear Domain node GVM metadata properties
            session.run(
                """
                MATCH (d:Domain {user_id: $uid, project_id: $pid})
                WHERE d.gvm_scan_timestamp IS NOT NULL
                REMOVE d.gvm_scan_timestamp, d.gvm_total_vulnerabilities,
                       d.gvm_critical, d.gvm_high, d.gvm_medium, d.gvm_low
                """,
                uid=user_id, pid=project_id
            )

            total = (stats["vulnerabilities_deleted"] + stats["cves_deleted"] +
                     stats["technologies_deleted"] + stats["traceroutes_deleted"] +
                     stats["certificates_deleted"] + stats["exploits_gvm_deleted"] +
                     stats["relationships_deleted"])
            print(f"[*][graph-db] Cleared GVM data: {total} items removed, "
                  f"{stats['technologies_cleaned']} shared technologies cleaned")

        return stats
