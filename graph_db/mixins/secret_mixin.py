"""
SecretMixin: Secret detection graph operations (GitHub hunt + TruffleHog).

Provides methods to ingest secret detection results:
- clear_github_hunt_data: wipe GitHub hunt data for a project
- update_graph_from_github_hunt: ingest GitHub secret hunt scan results
- clear_trufflehog_data: wipe TruffleHog data for a project
- update_graph_from_trufflehog: ingest TruffleHog secret scan results
"""

from datetime import datetime


class SecretMixin:
    def clear_github_hunt_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GitHub Secret Hunt nodes and relationships for a project.

        Preserves all recon and GVM data. Only removes:
        - GithubSecret / GithubSensitiveFile nodes (leaf findings)
        - GithubPath nodes
        - GithubRepository nodes
        - GithubHunt nodes
        - All relationships between them and to Domain

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted items
        """
        stats = {
            "secrets_deleted": 0,
            "sensitive_files_deleted": 0,
            "paths_deleted": 0,
            "repositories_deleted": 0,
            "hunts_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete leaf nodes first (GithubSecret)
            result = session.run(
                """
                MATCH (gs:GithubSecret {user_id: $uid, project_id: $pid})
                DETACH DELETE gs
                RETURN count(gs) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["secrets_deleted"] = record["deleted"]

            # 2. Delete leaf nodes (GithubSensitiveFile)
            result = session.run(
                """
                MATCH (gsf:GithubSensitiveFile {user_id: $uid, project_id: $pid})
                DETACH DELETE gsf
                RETURN count(gsf) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["sensitive_files_deleted"] = record["deleted"]

            # 3. Delete old GithubFinding nodes (from previous schema version)
            session.run(
                "MATCH (gf:GithubFinding {user_id: $uid, project_id: $pid}) DETACH DELETE gf",
                uid=user_id, pid=project_id
            )

            # 4. Delete GithubPath nodes
            result = session.run(
                """
                MATCH (gp:GithubPath {user_id: $uid, project_id: $pid})
                DETACH DELETE gp
                RETURN count(gp) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["paths_deleted"] = record["deleted"]

            # 5. Delete GithubRepository nodes
            result = session.run(
                """
                MATCH (gr:GithubRepository {user_id: $uid, project_id: $pid})
                DETACH DELETE gr
                RETURN count(gr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["repositories_deleted"] = record["deleted"]

            # 6. Delete GithubHunt nodes
            result = session.run(
                """
                MATCH (gh:GithubHunt {user_id: $uid, project_id: $pid})
                DETACH DELETE gh
                RETURN count(gh) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["hunts_deleted"] = record["deleted"]

            total = sum(stats.values())
            print(f"[*][graph-db] Cleared GitHub Hunt data: {total} items removed")

        return stats

    def update_graph_from_github_hunt(self, github_hunt_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with GitHub Secret Hunt scan results.

        Node hierarchy (5 levels):
        - GithubHunt node (scan metadata: target, timestamps, statistics)
        - GithubRepository nodes (each scanned repository)
        - GithubPath nodes (each unique file path within a repository)
        - GithubSecret nodes (SECRET findings — leaked credentials, API keys, etc.)
        - GithubSensitiveFile nodes (SENSITIVE_FILE findings — .env, config files, etc.)

        Relationships:
        - Domain -[:HAS_GITHUB_HUNT]-> GithubHunt
        - GithubHunt -[:HAS_REPOSITORY]-> GithubRepository
        - GithubRepository -[:HAS_PATH]-> GithubPath
        - GithubPath -[:CONTAINS_SECRET]-> GithubSecret
        - GithubPath -[:CONTAINS_SENSITIVE_FILE]-> GithubSensitiveFile

        Filtering: HIGH_ENTROPY findings are excluded (too noisy).
        Deduplication: Findings across commits are deduplicated by repository+path+secret_type.

        Args:
            github_hunt_data: The GitHub hunt JSON data (top-level with target, findings, statistics)
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "hunt_created": 0,
            "repositories_created": 0,
            "paths_created": 0,
            "secrets_created": 0,
            "sensitive_files_created": 0,
            "relationships_created": 0,
            "findings_skipped_high_entropy": 0,
            "findings_deduplicated": 0,
            "errors": []
        }

        # Validate input
        target = github_hunt_data.get("target")
        findings = github_hunt_data.get("findings", [])
        if not target:
            stats["errors"].append("No target found in github_hunt_data")
            return stats

        scan_statistics = github_hunt_data.get("statistics", {})

        with self.driver.session() as session:

            # Clear previous GitHub hunt data for this project
            clear_stats = self.clear_github_hunt_data(user_id, project_id)
            print(f"[*][graph-db] Pre-cleared: {clear_stats}")

            # 1. Create GithubHunt node (scan metadata)
            hunt_id = f"github-hunt-{user_id}-{project_id}"
            hunt_props = {
                "id": hunt_id,
                "user_id": user_id,
                "project_id": project_id,
                "target": target,
                "scan_start_time": github_hunt_data.get("scan_start_time", ""),
                "scan_end_time": github_hunt_data.get("scan_end_time", ""),
                "duration_seconds": github_hunt_data.get("duration_seconds", 0),
                "status": github_hunt_data.get("status", "unknown"),
                "repos_scanned": scan_statistics.get("repos_scanned", 0),
                "files_scanned": scan_statistics.get("files_scanned", 0),
                "commits_scanned": scan_statistics.get("commits_scanned", 0),
                "secrets_found": scan_statistics.get("secrets_found", 0),
                "sensitive_files": scan_statistics.get("sensitive_files", 0),
            }

            try:
                session.run(
                    """
                    MERGE (gh:GithubHunt {id: $id})
                    SET gh += $props, gh.updated_at = datetime()
                    """,
                    id=hunt_id, props=hunt_props
                )
                stats["hunt_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create GithubHunt node: {e}")
                print(f"[!][graph-db] GithubHunt creation failed: {e}")
                return stats

            # 2. Link GithubHunt to Domain node
            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (gh:GithubHunt {id: $hunt_id})
                    MERGE (d)-[:HAS_GITHUB_HUNT]->(gh)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, hunt_id=hunt_id
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
                else:
                    print(f"[!][graph-db] Warning: No Domain node found for user_id={user_id}, project_id={project_id}")
            except Exception as e:
                stats["errors"].append(f"Failed to link GithubHunt to Domain: {e}")

            # 3. Process findings (skip HIGH_ENTROPY, deduplicate across commits)
            seen_findings = set()  # dedup key: repo:path:secret_type
            created_repos = set()
            created_paths = set()  # dedup key: repo:path

            for finding in findings:
                finding_type = finding.get("type", "")

                # Skip HIGH_ENTROPY findings
                if finding_type == "HIGH_ENTROPY":
                    stats["findings_skipped_high_entropy"] += 1
                    continue

                # Only process SECRET and SENSITIVE_FILE
                if finding_type not in ("SECRET", "SENSITIVE_FILE"):
                    continue

                repository = finding.get("repository", "")
                path = finding.get("path", "")
                secret_type = finding.get("secret_type", "")

                if not repository or not secret_type:
                    continue

                # Strip commit hash from path: "file.py (commit: abc123)" → "file.py"
                clean_path = path.split(" (commit:")[0].strip()

                # Deduplicate: same repo + path + secret_type across commits
                dedup_key = f"{repository}:{clean_path}:{secret_type}"
                if dedup_key in seen_findings:
                    stats["findings_deduplicated"] += 1
                    continue
                seen_findings.add(dedup_key)

                repo_id = f"github-repo-{user_id}-{project_id}-{repository}"
                path_id = f"github-path-{user_id}-{project_id}-{hash(f'{repository}:{clean_path}') & 0xFFFFFFFF:08x}"

                # 3a. Create/merge GithubRepository node
                if repository not in created_repos:
                    repo_props = {
                        "id": repo_id,
                        "name": repository,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        session.run(
                            "MERGE (gr:GithubRepository {id: $id}) SET gr += $props, gr.updated_at = datetime()",
                            id=repo_id, props=repo_props
                        )
                        stats["repositories_created"] += 1
                        created_repos.add(repository)

                        # Link GithubHunt → GithubRepository
                        session.run(
                            """
                            MATCH (gh:GithubHunt {id: $hunt_id})
                            MATCH (gr:GithubRepository {id: $repo_id})
                            MERGE (gh)-[:HAS_REPOSITORY]->(gr)
                            """,
                            hunt_id=hunt_id, repo_id=repo_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create repo {repository}: {e}")
                        continue

                # 3b. Create/merge GithubPath node
                path_key = f"{repository}:{clean_path}"
                if path_key not in created_paths:
                    path_props = {
                        "id": path_id,
                        "path": clean_path,
                        "repository": repository,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        session.run(
                            "MERGE (gp:GithubPath {id: $id}) SET gp += $props, gp.updated_at = datetime()",
                            id=path_id, props=path_props
                        )
                        stats["paths_created"] += 1
                        created_paths.add(path_key)

                        # Link GithubRepository → GithubPath
                        session.run(
                            """
                            MATCH (gr:GithubRepository {id: $repo_id})
                            MATCH (gp:GithubPath {id: $path_id})
                            MERGE (gr)-[:HAS_PATH]->(gp)
                            """,
                            repo_id=repo_id, path_id=path_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create path {path_key}: {e}")
                        continue

                # 3c. Create leaf finding node (GithubSecret or GithubSensitiveFile)
                finding_hash = f"{hash(dedup_key) & 0xFFFFFFFF:08x}"
                details = finding.get("details", {})

                if finding_type == "SECRET":
                    node_id = f"github-secret-{user_id}-{project_id}-{finding_hash}"
                    node_props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "secret_type": secret_type,
                        "repository": repository,
                        "path": clean_path,
                        "timestamp": finding.get("timestamp", ""),
                    }
                    if details.get("matches"):
                        node_props["matches"] = details["matches"]
                    if details.get("sample"):
                        node_props["sample"] = details["sample"]

                    try:
                        session.run(
                            "MERGE (gs:GithubSecret {id: $id}) SET gs += $props, gs.updated_at = datetime()",
                            id=node_id, props=node_props
                        )
                        stats["secrets_created"] += 1

                        # Link GithubPath → GithubSecret
                        session.run(
                            """
                            MATCH (gp:GithubPath {id: $path_id})
                            MATCH (gs:GithubSecret {id: $node_id})
                            MERGE (gp)-[:CONTAINS_SECRET]->(gs)
                            """,
                            path_id=path_id, node_id=node_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create secret {dedup_key}: {e}")

                elif finding_type == "SENSITIVE_FILE":
                    node_id = f"github-sensitivefi-{user_id}-{project_id}-{finding_hash}"
                    node_props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        "secret_type": secret_type,
                        "repository": repository,
                        "path": clean_path,
                        "timestamp": finding.get("timestamp", ""),
                    }

                    try:
                        session.run(
                            "MERGE (gsf:GithubSensitiveFile {id: $id}) SET gsf += $props, gsf.updated_at = datetime()",
                            id=node_id, props=node_props
                        )
                        stats["sensitive_files_created"] += 1

                        # Link GithubPath → GithubSensitiveFile
                        session.run(
                            """
                            MATCH (gp:GithubPath {id: $path_id})
                            MATCH (gsf:GithubSensitiveFile {id: $node_id})
                            MERGE (gp)-[:CONTAINS_SENSITIVE_FILE]->(gsf)
                            """,
                            path_id=path_id, node_id=node_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create sensitive file {dedup_key}: {e}")

            # Print summary
            print(f"\n[+] GitHub Hunt Graph Update Summary:")
            print(f"[+][graph-db] Created {stats['hunt_created']} GithubHunt node")
            print(f"[+][graph-db] Created {stats['repositories_created']} GithubRepository nodes")
            print(f"[+][graph-db] Created {stats['paths_created']} GithubPath nodes")
            print(f"[+][graph-db] Created {stats['secrets_created']} GithubSecret nodes")
            print(f"[+][graph-db] Created {stats['sensitive_files_created']} GithubSensitiveFile nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Skipped {stats['findings_skipped_high_entropy']} HIGH_ENTROPY findings")
            print(f"[+][graph-db] Deduplicated {stats['findings_deduplicated']} cross-commit findings")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

    # =========================================================================
    # TruffleHog Secret Scanner — Graph Integration
    # =========================================================================

    def clear_trufflehog_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only TruffleHog Secret Scanner nodes and relationships for a project.

        Preserves all recon, GVM, and GitHub Hunt data. Only removes:
        - TrufflehogFinding nodes (leaf findings)
        - TrufflehogRepository nodes
        - TrufflehogScan nodes
        - All relationships between them and to Domain

        Args:
            user_id: User identifier
            project_id: Project identifier

        Returns:
            dict with counts of deleted items
        """
        stats = {
            "findings_deleted": 0,
            "repositories_deleted": 0,
            "scans_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Delete leaf nodes first (TrufflehogFinding)
            result = session.run(
                """
                MATCH (tf:TrufflehogFinding {user_id: $uid, project_id: $pid})
                DETACH DELETE tf
                RETURN count(tf) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["findings_deleted"] = record["deleted"]

            # 2. Delete TrufflehogRepository nodes
            result = session.run(
                """
                MATCH (tr:TrufflehogRepository {user_id: $uid, project_id: $pid})
                DETACH DELETE tr
                RETURN count(tr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["repositories_deleted"] = record["deleted"]

            # 3. Delete TrufflehogScan nodes
            result = session.run(
                """
                MATCH (ts:TrufflehogScan {user_id: $uid, project_id: $pid})
                DETACH DELETE ts
                RETURN count(ts) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["scans_deleted"] = record["deleted"]

            total = sum(stats.values())
            print(f"[*][graph-db] Cleared TruffleHog data: {total} items removed")

        return stats

    def update_graph_from_trufflehog(self, trufflehog_data: dict, user_id: str, project_id: str) -> dict:
        """
        Update the Neo4j graph database with TruffleHog scan results.

        Node hierarchy (3 levels):
        - TrufflehogScan node (scan metadata: target, timestamps, statistics)
        - TrufflehogRepository nodes (each scanned repository)
        - TrufflehogFinding nodes (each secret finding with verification status)

        Relationships:
        - Domain -[:HAS_TRUFFLEHOG_SCAN]-> TrufflehogScan
        - TrufflehogScan -[:HAS_REPOSITORY]-> TrufflehogRepository
        - TrufflehogRepository -[:HAS_FINDING]-> TrufflehogFinding

        Deduplication: Findings are deduplicated by repository+file+line+detector_name.

        Args:
            trufflehog_data: The TruffleHog scan JSON data (top-level with target, findings, statistics)
            user_id: User identifier for multi-tenant isolation
            project_id: Project identifier for multi-tenant isolation

        Returns:
            Dictionary with statistics about created nodes/relationships
        """
        stats = {
            "scan_created": 0,
            "repositories_created": 0,
            "findings_created": 0,
            "relationships_created": 0,
            "findings_deduplicated": 0,
            "errors": []
        }

        # Validate input
        target = trufflehog_data.get("target")
        findings = trufflehog_data.get("findings", [])
        if not target:
            stats["errors"].append("No target found in trufflehog_data")
            return stats

        scan_statistics = trufflehog_data.get("statistics", {})

        with self.driver.session() as session:

            # Clear previous TruffleHog data for this project
            clear_stats = self.clear_trufflehog_data(user_id, project_id)
            print(f"[*][graph-db] Pre-cleared: {clear_stats}")

            # 1. Create TrufflehogScan node (scan metadata)
            scan_id = f"trufflehog-scan-{user_id}-{project_id}"
            scan_props = {
                "id": scan_id,
                "user_id": user_id,
                "project_id": project_id,
                "target": target,
                "scan_start_time": trufflehog_data.get("scan_start_time", ""),
                "scan_end_time": trufflehog_data.get("scan_end_time", ""),
                "duration_seconds": trufflehog_data.get("duration_seconds", 0),
                "status": trufflehog_data.get("status", "unknown"),
                "total_findings": scan_statistics.get("total_findings", 0),
                "verified_findings": scan_statistics.get("verified_findings", 0),
                "unverified_findings": scan_statistics.get("unverified_findings", 0),
                "repositories_scanned": scan_statistics.get("repositories_scanned", 0),
            }

            try:
                session.run(
                    """
                    MERGE (ts:TrufflehogScan {id: $id})
                    SET ts += $props, ts.updated_at = datetime()
                    """,
                    id=scan_id, props=scan_props
                )
                stats["scan_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create TrufflehogScan node: {e}")
                print(f"[!][graph-db] TrufflehogScan creation failed: {e}")
                return stats

            # 2. Link TrufflehogScan to Domain node
            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (ts:TrufflehogScan {id: $scan_id})
                    MERGE (d)-[:HAS_TRUFFLEHOG_SCAN]->(ts)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, scan_id=scan_id
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
                else:
                    print(f"[!][graph-db] Warning: No Domain node found for user_id={user_id}, project_id={project_id}")
            except Exception as e:
                stats["errors"].append(f"Failed to link TrufflehogScan to Domain: {e}")

            # 3. Process findings (deduplicate by repo+file+line+detector)
            seen_findings = set()
            created_repos = set()

            for finding in findings:
                repository = finding.get("repository", "")
                file_path = finding.get("file", "")
                line = finding.get("line", 0)
                detector_name = finding.get("detector_name", "")

                if not detector_name:
                    continue

                # Deduplicate
                dedup_key = f"{repository}:{file_path}:{line}:{detector_name}"
                if dedup_key in seen_findings:
                    stats["findings_deduplicated"] += 1
                    continue
                seen_findings.add(dedup_key)

                # Generate IDs
                repo_hash = f"{hash(f'{user_id}:{project_id}:{repository}') & 0xFFFFFFFF:08x}"
                repo_id = f"trufflehog-repo-{user_id}-{project_id}-{repo_hash}"
                finding_hash = f"{hash(dedup_key) & 0xFFFFFFFF:08x}"
                finding_id = f"trufflehog-finding-{user_id}-{project_id}-{finding_hash}"

                # 3a. Create/merge TrufflehogRepository node
                if repository and repository not in created_repos:
                    repo_props = {
                        "id": repo_id,
                        "name": repository,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        session.run(
                            "MERGE (tr:TrufflehogRepository {id: $id}) SET tr += $props, tr.updated_at = datetime()",
                            id=repo_id, props=repo_props
                        )
                        stats["repositories_created"] += 1
                        created_repos.add(repository)

                        # Link TrufflehogScan → TrufflehogRepository
                        session.run(
                            """
                            MATCH (ts:TrufflehogScan {id: $scan_id})
                            MATCH (tr:TrufflehogRepository {id: $repo_id})
                            MERGE (ts)-[:HAS_REPOSITORY]->(tr)
                            """,
                            scan_id=scan_id, repo_id=repo_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create repo {repository}: {e}")
                        continue

                # 3b. Create TrufflehogFinding node
                finding_props = {
                    "id": finding_id,
                    "user_id": user_id,
                    "project_id": project_id,
                    "detector_name": detector_name,
                    "detector_description": finding.get("detector_description", ""),
                    "verified": finding.get("verified", False),
                    "redacted": finding.get("redacted", ""),
                    "repository": repository,
                    "file": file_path,
                    "commit": finding.get("commit", ""),
                    "line": line,
                    "link": finding.get("link", ""),
                    "timestamp": finding.get("timestamp", ""),
                    "extra_data": finding.get("extra_data", "{}"),
                }

                try:
                    session.run(
                        "MERGE (tf:TrufflehogFinding {id: $id}) SET tf += $props, tf.updated_at = datetime()",
                        id=finding_id, props=finding_props
                    )
                    stats["findings_created"] += 1

                    # Link TrufflehogRepository → TrufflehogFinding
                    if repository:
                        session.run(
                            """
                            MATCH (tr:TrufflehogRepository {id: $repo_id})
                            MATCH (tf:TrufflehogFinding {id: $finding_id})
                            MERGE (tr)-[:HAS_FINDING]->(tf)
                            """,
                            repo_id=repo_id, finding_id=finding_id
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Failed to create finding {dedup_key}: {e}")

            # Print summary
            print(f"\n[+] TruffleHog Graph Update Summary:")
            print(f"[+][graph-db] Created {stats['scan_created']} TrufflehogScan node")
            print(f"[+][graph-db] Created {stats['repositories_created']} TrufflehogRepository nodes")
            print(f"[+][graph-db] Created {stats['findings_created']} TrufflehogFinding nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Deduplicated {stats['findings_deduplicated']} findings")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        return stats

