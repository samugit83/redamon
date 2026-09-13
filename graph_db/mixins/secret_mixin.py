"""
SecretMixin: Secret detection graph operations (GitHub hunt + TruffleHog).

Provides methods to ingest secret detection results:
- clear_github_hunt_data: wipe GitHub hunt data for a project
- update_graph_from_github_hunt: ingest GitHub secret hunt scan results
- clear_trufflehog_data: wipe TruffleHog data for a project, or for ONE source
- update_graph_from_trufflehog: ingest one TruffleHog source's scan results
"""

from graph_db.mixins.base_mixin import run_timestamp
import hashlib
from datetime import datetime
from typing import Optional


class SecretMixin:
    @staticmethod
    def _github_digest(*parts: str) -> str:
        """Stable 12-hex identity digest for GitHub hunt node ids.

        Replaces the builtin hash(), which is randomised per process via
        PYTHONHASHSEED and so gave the same file a different node id on every
        scan — and was truncated to 32 bits on top of that. The blanket
        pre-clear hid it; anything that stops wiping first would surface it as
        duplicated nodes.
        """
        return hashlib.sha1("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:12]

    def clear_github_hunt_data(self, user_id: str, project_id: str) -> dict:
        """
        Delete only GitHub Secret Hunt nodes and relationships for a project.

        Preserves all recon and GVM data. Only removes:
        - GithubSecret / GithubSensitiveFile nodes (leaf findings)
        - GithubPath nodes
        - GithubHunt nodes
        - GithubRepository nodes THIS scanner owns alone
        - All relationships between them and to Domain

        GithubRepository is a SHARED node: `ensure_github_repository` in
        supply_chain_mixin deliberately MERGEs the same id so a repo scanned
        both ways is one node. A blanket `DETACH DELETE` here therefore wiped
        the supply-chain scan's `GithubRepository -[:DEPENDS_ON]-> Package`
        edges and left its packages floating. The repo sweep runs last and only
        takes nodes with no relationship left once the hunt's own subtree is
        gone, so a supply-chain anchor survives.

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
            "repositories_kept": 0,
            "hunts_deleted": 0,
        }

        with self.driver.session() as session:
            # 1. Leaf FINDINGS are no longer deleted here (X7). Deleting them
            # up front deleted the operator's mutes and verdicts with them, and
            # orphaned any fix item linked to one. They are pruned after a
            # SUCCESSFUL ingest instead, by `prune_unseen_findings`, which keeps
            # anything a person touched and stamps it stale.
            #
            # Only nodes this scanner LOST TRACK OF are removed: a partial node
            # from a crashed run with no path above it.
            result = session.run(
                """
                MATCH (gs:GithubSecret {user_id: $uid, project_id: $pid})
                WHERE NOT EXISTS { (:GithubPath)-[:CONTAINS_SECRET]->(gs) }
                  AND NOT gs:Muted
                  AND coalesce(gs.triage_source, '') <> 'human'
                DETACH DELETE gs
                RETURN count(gs) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["secrets_deleted"] = record["deleted"]

            # 2. Same for the sensitive-file findings (X7).
            result = session.run(
                """
                MATCH (gsf:GithubSensitiveFile {user_id: $uid, project_id: $pid})
                WHERE NOT EXISTS { (:GithubPath)-[:CONTAINS_SENSITIVE_FILE]->(gsf) }
                  AND NOT gsf:Muted
                  AND coalesce(gsf.triage_source, '') <> 'human'
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

            # 4. Delete GithubPath nodes, EXCEPT any still holding a finding a
            #    person touched. Deleting those would orphan the preserved
            #    finding, and the sweep in step 1 would take it on the next run,
            #    undoing the whole point of X7.
            result = session.run(
                """
                MATCH (gp:GithubPath {user_id: $uid, project_id: $pid})
                WHERE NOT EXISTS {
                  MATCH (gp)-[:CONTAINS_SECRET|CONTAINS_SENSITIVE_FILE]->(f)
                  WHERE f:Muted OR coalesce(f.triage_source, '') = 'human'
                }
                DETACH DELETE gp
                RETURN count(gp) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["paths_deleted"] = record["deleted"]

            # 5. Delete GithubHunt nodes — before the repo sweep, so the hunt's
            #    own HAS_REPOSITORY edges no longer count as "still referenced".
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

            # 6. Delete only the GithubRepository nodes nothing else holds.
            result = session.run(
                """
                MATCH (gr:GithubRepository {user_id: $uid, project_id: $pid})
                WHERE NOT (gr)--()
                DELETE gr
                RETURN count(gr) as deleted
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["repositories_deleted"] = record["deleted"]

            result = session.run(
                """
                MATCH (gr:GithubRepository {user_id: $uid, project_id: $pid})
                RETURN count(gr) as kept
                """,
                uid=user_id, pid=project_id
            )
            record = result.single()
            if record:
                stats["repositories_kept"] = record["kept"]

            total = sum(v for k, v in stats.items() if k != "repositories_kept")
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

        # Taken BEFORE the ingest: everything it writes gets a later
        # `updated_at` and therefore survives the prune at the end (X7).
        run_started_at = run_timestamp()

        with self.driver.session() as session:

            # Clear the hunt's CONTAINERS (paths, repos, the hunt node). The
            # findings are no longer deleted here; they are pruned after a
            # successful ingest, below.
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
                    MERGE (gh:GithubHunt {id: $id, user_id: $props.user_id,
                                         project_id: $props.project_id})
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
                    MATCH (gh:GithubHunt {id: $hunt_id, user_id: $uid, project_id: $pid})
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
                path_id = f"github-path-{user_id}-{project_id}-{self._github_digest(repository, clean_path)}"

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
                            "MERGE (gr:GithubRepository {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET gr += $props, gr.updated_at = datetime()",
                            id=repo_id, props=repo_props
                        )
                        stats["repositories_created"] += 1
                        created_repos.add(repository)

                        # Link GithubHunt → GithubRepository
                        session.run(
                            """
                            MATCH (gh:GithubHunt {id: $hunt_id, user_id: $uid,
                                                  project_id: $pid})
                            MATCH (gr:GithubRepository {id: $repo_id, user_id: $uid,
                                                        project_id: $pid})
                            MERGE (gh)-[:HAS_REPOSITORY]->(gr)
                            """,
                            hunt_id=hunt_id, repo_id=repo_id,
                            uid=user_id, pid=project_id
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
                            "MERGE (gp:GithubPath {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET gp += $props, gp.updated_at = datetime()",
                            id=path_id, props=path_props
                        )
                        stats["paths_created"] += 1
                        created_paths.add(path_key)

                        # Link GithubRepository → GithubPath
                        session.run(
                            """
                            MATCH (gr:GithubRepository {id: $repo_id, user_id: $uid,
                                                        project_id: $pid})
                            MATCH (gp:GithubPath {id: $path_id, user_id: $uid,
                                                  project_id: $pid})
                            MERGE (gr)-[:HAS_PATH]->(gp)
                            """,
                            repo_id=repo_id, path_id=path_id,
                            uid=user_id, pid=project_id
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create path {path_key}: {e}")
                        continue

                # 3c. Create leaf finding node (GithubSecret or GithubSensitiveFile)
                finding_hash = self._github_digest(dedup_key)
                details = finding.get("details", {})

                if finding_type == "SECRET":
                    node_id = f"github-secret-{user_id}-{project_id}-{finding_hash}"
                    node_props = {
                        "id": node_id,
                        "user_id": user_id,
                        "project_id": project_id,
                        # X7: the prune is scoped BY SOURCE, so a finding with
                        # none can never be pruned, and a GitHub-hunt finding
                        # would then never be cleaned up at all.
                        "source": "github_hunt",
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
                            "MERGE (gs:GithubSecret {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET gs += $props, gs.updated_at = datetime()",
                            id=node_id, props=node_props
                        )
                        stats["secrets_created"] += 1

                        # Link GithubPath → GithubSecret
                        session.run(
                            """
                            MATCH (gp:GithubPath {id: $path_id, user_id: $uid,
                                                  project_id: $pid})
                            MATCH (gs:GithubSecret {id: $node_id, user_id: $uid,
                                                    project_id: $pid})
                            MERGE (gp)-[:CONTAINS_SECRET]->(gs)
                            """,
                            path_id=path_id, node_id=node_id,
                            uid=user_id, pid=project_id
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
                        # X7: the prune is scoped BY SOURCE, so a finding with
                        # none can never be pruned, and a GitHub-hunt finding
                        # would then never be cleaned up at all.
                        "source": "github_hunt",
                        "secret_type": secret_type,
                        "repository": repository,
                        "path": clean_path,
                        "timestamp": finding.get("timestamp", ""),
                    }

                    try:
                        session.run(
                            "MERGE (gsf:GithubSensitiveFile {id: $id, user_id: $props.user_id, project_id: $props.project_id}) SET gsf += $props, gsf.updated_at = datetime()",
                            id=node_id, props=node_props
                        )
                        stats["sensitive_files_created"] += 1

                        # Link GithubPath → GithubSensitiveFile
                        session.run(
                            """
                            MATCH (gp:GithubPath {id: $path_id, user_id: $uid,
                                                  project_id: $pid})
                            MATCH (gsf:GithubSensitiveFile {id: $node_id, user_id: $uid,
                                                            project_id: $pid})
                            MERGE (gp)-[:CONTAINS_SENSITIVE_FILE]->(gsf)
                            """,
                            path_id=path_id, node_id=node_id,
                            uid=user_id, pid=project_id
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

        # X7: remove the findings this scan stopped reporting, now that the
        # ingest has actually produced some. A run that wrote NOTHING is not
        # evidence the findings are gone - it is evidence the scan failed - so
        # the prune is skipped rather than emptying the project.
        if stats["secrets_created"] or stats["sensitive_files_created"]:
            stats["pruned"] = self.prune_unseen_findings(
                user_id, project_id, ["github_hunt"], run_started_at)

        return stats

    # =========================================================================
    # TruffleHog Secret Scanner — Graph Integration
    # =========================================================================
    #
    # Multi-source model. One MultiscannerScan per (project, SOURCE), so a Docker
    # run and a HuggingFace run coexist instead of overwriting one another:
    #
    #   Domain -[:HAS_MULTISCANNER_SCAN]-> MultiscannerScan     (one per project+source)
    #         -[:HAS_ASSET]-> <asset label>                 (one per scanned thing)
    #               -[:HAS_FINDING]-> MultiscannerFinding     (one per deduped secret)
    #
    # Five asset labels, not sixteen: a Docker image, an S3 bucket, an HF model
    # and a Jenkins instance are not "repositories", but the graph renderer draws
    # a node from labels[0] (a SINGLE label, and Neo4j does not order labels), so
    # every node carries exactly one. Grouping by asset SHAPE gives five, and the
    # git family keeps MultiscannerRepository — its existing colour and history.

    #: Asset shape -> label. The scan's own source decides which is used; a
    #: finding never picks its label from the metadata, or a mis-keyed result
    #: would land under another source's label.
    TRUFFLEHOG_ASSET_LABELS = {
        "repository": "MultiscannerRepository",
        "image": "MultiscannerImage",
        "model": "MultiscannerModel",
        "bucket": "MultiscannerBucket",
        "endpoint": "MultiscannerEndpoint",
    }

    #: The label set the scoped clear has to sweep. Missing one leaks its nodes.
    TRUFFLEHOG_ALL_ASSET_LABELS = (
        "MultiscannerRepository", "MultiscannerImage", "MultiscannerModel",
        "MultiscannerBucket", "MultiscannerEndpoint",
    )

    @staticmethod
    def _trufflehog_digest(*parts: str) -> str:
        """Stable 12-hex identity digest.

        MUST match scanners/trufflehog_scan/findings.py:digest — the two run in
        different images and cannot import each other, and
        tests/test_trufflehog_stable_ids.py asserts they agree. Replaces the
        builtin hash(), which is randomised per process via PYTHONHASHSEED and so
        produced a different node id for the same repository on every run. The
        old blanket pre-clear hid that; with source-scoped clearing it would
        surface as duplicated and orphaned nodes.
        """
        return hashlib.sha1("\x1f".join(str(p) for p in parts).encode()).hexdigest()[:12]

    @staticmethod
    def _trufflehog_validation_status(finding: dict) -> str:
        """Normalise a finding into the vocabulary the :Secret nodes already use.

        Prefers the scanner's own field (it alone knows whether verification was
        switched off for the run); the derivation is only a fallback for findings
        written before the field existed. 'unvalidated' (checked, dead) and
        'unverified' (never checked) must not collapse — the difference decides
        whether a pentest report can call a credential safe.
        """
        status = str(finding.get("validation_status") or "").strip()
        if status:
            return status
        if finding.get("verified"):
            return "validated"
        if finding.get("verification_error"):
            return "verify_error"
        return "unvalidated"

    def clear_trufflehog_data(self, user_id: str, project_id: str,
                              source: Optional[str] = None) -> dict:
        """Delete TruffleHog nodes for a project.

        With `source` set, delete ONLY that source's subgraph. This is the change
        that must not be missed: the old blanket clear ran at the head of every
        ingest, so a Docker scan finishing would DETACH DELETE every HuggingFace
        finding — no error, no warning, and a perfect-looking JSON artifact to go
        with it. Ingest always passes a source; only project deletion passes None.

        Legacy nodes (written before the multi-source model, when the scanner was
        github-only and stamped no `source`) are swept together with the `github`
        source, which is what they are. Any other scoped clear leaves them alone.
        """
        stats = {"findings_deleted": 0, "assets_deleted": 0, "scans_deleted": 0}
        scoped = bool(source)
        # Untagged legacy data is github data; nothing else may claim it.
        legacy = " OR n.source IS NULL" if source == "github" else ""
        where = f" AND (n.source = $source{legacy})" if scoped else ""
        params = {"uid": user_id, "pid": project_id}
        if scoped:
            params["source"] = source

        with self.driver.session() as session:
            # Leaves first, so an interrupted clear cannot leave a finding
            # dangling off a deleted asset.
            # X7: findings a person touched are NOT deleted. Deleting them
            # deleted the mute they applied and the verdict they recorded with
            # them, on every scan of this source. The rest are still cleared
            # here rather than pruned afterwards, because this clear is already
            # scoped to ONE source's previous run and the ingest that follows
            # rebuilds it completely.
            result = session.run(
                f"""
                MATCH (n:MultiscannerFinding)
                WHERE n.user_id = $uid AND n.project_id = $pid{where}
                  AND NOT n:Muted
                  AND coalesce(n.triage_source, '') <> 'human'
                DETACH DELETE n
                RETURN count(n) as deleted
                """,
                **params,
            )
            record = result.single()
            if record:
                stats["findings_deleted"] = record["deleted"]

            for label in self.TRUFFLEHOG_ALL_ASSET_LABELS:
                result = session.run(
                    f"""
                    MATCH (n:{label})
                    WHERE n.user_id = $uid AND n.project_id = $pid{where}
                      // X7: an asset still holding a finding a person touched
                      // survives, or that finding is orphaned and the board can
                      // no longer say where it was found.
                      AND NOT EXISTS {{
                        MATCH (n)-[:HAS_FINDING]->(f:MultiscannerFinding)
                        WHERE f:Muted OR coalesce(f.triage_source, '') = 'human'
                      }}
                    DETACH DELETE n
                    RETURN count(n) as deleted
                    """,
                    **params,
                )
                record = result.single()
                if record:
                    stats["assets_deleted"] += record["deleted"]

            result = session.run(
                f"""
                MATCH (n:MultiscannerScan)
                WHERE n.user_id = $uid AND n.project_id = $pid{where}
                DETACH DELETE n
                RETURN count(n) as deleted
                """,
                **params,
            )
            record = result.single()
            if record:
                stats["scans_deleted"] = record["deleted"]

            total = sum(stats.values())
            scope = f"source={source}" if scoped else "ALL sources"
            print(f"[*][graph-db] Cleared TruffleHog data ({scope}): {total} items removed")

        return stats

    def update_graph_from_trufflehog(self, trufflehog_data: dict, user_id: str,
                                     project_id: str) -> dict:
        """Write ONE source's TruffleHog run into the graph.

        Called by the orchestrator after the scan container exits — the clean
        half of the dirty/clean split. Every string in `trufflehog_data` is
        target-controlled (repo names, image tags, file paths), so every value
        goes in as a Cypher PARAMETER; nothing is formatted into a query string.

        Deduplication is source-scoped: the same secret found by two sources is
        two findings, because the second source's context is a separate fact.
        """
        stats = {
            "scan_created": 0,
            "assets_created": 0,
            "findings_created": 0,
            "relationships_created": 0,
            "findings_deduplicated": 0,
            "errors": [],
        }

        source = str(trufflehog_data.get("source") or "").strip()
        if not source:
            stats["errors"].append("No source in trufflehog_data; refusing to write")
            return stats

        target = trufflehog_data.get("target") or ""
        # `or []` rather than a .get default: a truncated or hand-edited artifact
        # can carry an explicit null, and the key being PRESENT means the default
        # never applies. The scan node is still written — losing the run record
        # too would hide that the scan happened at all.
        findings = trufflehog_data.get("findings") or []
        if not isinstance(findings, list):
            # Deliberately `type(findings)` and not its dunder name attribute:
            # tests/test_graph_db_refactor.py screens mixins for that literal to
            # catch stray main-guard blocks, with a plain substring match.
            stats["errors"].append(
                f"findings is {type(findings)}, not a list; ignoring them")
            findings = []
        scan_statistics = trufflehog_data.get("statistics") or {}
        asset_kind = trufflehog_data.get("asset_kind") or "endpoint"
        asset_label = self.TRUFFLEHOG_ASSET_LABELS.get(
            asset_kind, "MultiscannerEndpoint")

        # X7: taken BEFORE the clear and the ingest, so everything this run
        # writes has a later `updated_at` and survives the prune at the end.
        run_started_at = run_timestamp()

        with self.driver.session() as session:
            # SCOPED clear, never the blanket one: this reaps only this source's
            # previous run (and any partial nodes a crashed run left behind).
            clear_stats = self.clear_trufflehog_data(user_id, project_id, source=source)
            print(f"[*][graph-db] Pre-cleared {source}: {clear_stats}")

            scan_id = f"multiscanner-scan-{user_id}-{project_id}-{source}"
            scan_props = {
                "id": scan_id,
                "user_id": user_id,
                "project_id": project_id,
                "source": source,
                "source_label": trufflehog_data.get("source_label", source),
                "run_id": trufflehog_data.get("run_id", source),
                "target": target,
                "verification_enabled": bool(trufflehog_data.get("verification_enabled", True)),
                "scan_start_time": trufflehog_data.get("scan_start_time", ""),
                "scan_end_time": trufflehog_data.get("scan_end_time", ""),
                "duration_seconds": trufflehog_data.get("duration_seconds", 0),
                "status": trufflehog_data.get("status", "unknown"),
                "total_findings": scan_statistics.get("total_findings", 0),
                "verified_findings": scan_statistics.get("verified_findings", 0),
                "unverified_findings": scan_statistics.get("unverified_findings", 0),
                "validated_findings": scan_statistics.get("validated", 0),
                "assets_scanned": scan_statistics.get("assets_scanned", 0),
                # Kept for one release so report queries reading the old name
                # keep working (renamed to assets_scanned).
                "repositories_scanned": scan_statistics.get("assets_scanned", 0),
            }

            try:
                session.run(
                    """
                    MERGE (ts:MultiscannerScan {id: $id, user_id: $uid, project_id: $pid})
                    SET ts += $props, ts.updated_at = datetime()
                    """,
                    id=scan_id, uid=user_id, pid=project_id, props=scan_props,
                )
                stats["scan_created"] += 1
            except Exception as e:
                stats["errors"].append(f"Failed to create MultiscannerScan node: {e}")
                print(f"[!][graph-db] MultiscannerScan creation failed: {e}")
                return stats

            try:
                result = session.run(
                    """
                    MATCH (d:Domain {user_id: $uid, project_id: $pid})
                    MATCH (ts:MultiscannerScan {id: $scan_id, user_id: $uid, project_id: $pid})
                    MERGE (d)-[:HAS_MULTISCANNER_SCAN]->(ts)
                    RETURN count(*) as linked
                    """,
                    uid=user_id, pid=project_id, scan_id=scan_id,
                )
                record = result.single()
                if record and record["linked"] > 0:
                    stats["relationships_created"] += 1
                else:
                    print(f"[!][graph-db] Warning: No Domain node found for "
                          f"user_id={user_id}, project_id={project_id}")
            except Exception as e:
                stats["errors"].append(f"Failed to link MultiscannerScan to Domain: {e}")

            seen_findings = set()
            created_assets = set()

            for finding in findings:
                asset = finding.get("asset") or finding.get("repository") or ""
                location = finding.get("location") or finding.get("file") or ""
                line = finding.get("line", 0)
                detector_name = finding.get("detector_name", "")

                if not detector_name:
                    continue

                # Source-scoped: without the prefix, the same secret found by two
                # sources collapses into one node.
                dedup_key = f"{source}:{asset}:{location}:{line}:{detector_name}"
                if dedup_key in seen_findings:
                    stats["findings_deduplicated"] += 1
                    continue
                seen_findings.add(dedup_key)

                asset_id = (f"multiscanner-asset-{user_id}-{project_id}-{source}-"
                            f"{self._trufflehog_digest(user_id, project_id, source, asset)}")
                finding_id = (f"multiscanner-finding-{user_id}-{project_id}-{source}-"
                              f"{self._trufflehog_digest(user_id, project_id, dedup_key)}")

                if asset and asset not in created_assets:
                    asset_props = {
                        "id": asset_id,
                        "name": asset,
                        "source": source,
                        "asset_kind": asset_kind,
                        "scan_id": scan_id,
                        "user_id": user_id,
                        "project_id": project_id,
                    }
                    try:
                        # The label is interpolated because Cypher cannot
                        # parameterise one — it comes from OUR registry
                        # (TRUFFLEHOG_ASSET_LABELS), never from scan output.
                        session.run(
                            f"MERGE (ta:{asset_label} "
                            f"{{id: $id, user_id: $uid, project_id: $pid}}) "
                            f"SET ta += $props, ta.updated_at = datetime()",
                            id=asset_id, uid=user_id, pid=project_id, props=asset_props,
                        )
                        stats["assets_created"] += 1
                        created_assets.add(asset)

                        session.run(
                            f"""
                            MATCH (ts:MultiscannerScan {{id: $scan_id, user_id: $uid, project_id: $pid}})
                            MATCH (ta:{asset_label} {{id: $asset_id, user_id: $uid, project_id: $pid}})
                            MERGE (ts)-[:HAS_ASSET]->(ta)
                            """,
                            scan_id=scan_id, asset_id=asset_id, uid=user_id, pid=project_id,
                        )
                        stats["relationships_created"] += 1
                    except Exception as e:
                        stats["errors"].append(f"Failed to create asset {asset}: {e}")
                        continue

                finding_props = {
                    "id": finding_id,
                    "user_id": user_id,
                    "project_id": project_id,
                    "source": source,
                    "scan_id": scan_id,
                    "detector_name": detector_name,
                    "detector_description": finding.get("detector_description", ""),
                    "verified": finding.get("verified", False),
                    "validation_status": self._trufflehog_validation_status(finding),
                    "finding_kind": finding.get("finding_kind", "secret"),
                    "redacted": finding.get("redacted", ""),
                    "asset": asset,
                    "location": location,
                    # Deprecated aliases, one release, so existing report Cypher
                    # keeps matching while it is migrated.
                    "repository": asset,
                    "file": location,
                    "commit": finding.get("commit", ""),
                    "line": line,
                    "link": finding.get("link", ""),
                    "timestamp": finding.get("timestamp", ""),
                    "extra_data": finding.get("extra_data", "{}"),
                }

                try:
                    session.run(
                        """
                        MERGE (tf:MultiscannerFinding {id: $id, user_id: $uid, project_id: $pid})
                        SET tf += $props, tf.updated_at = datetime()
                        """,
                        id=finding_id, uid=user_id, pid=project_id, props=finding_props,
                    )
                    stats["findings_created"] += 1

                    if asset:
                        session.run(
                            f"""
                            MATCH (ta:{asset_label} {{id: $asset_id, user_id: $uid, project_id: $pid}})
                            MATCH (tf:MultiscannerFinding {{id: $finding_id, user_id: $uid, project_id: $pid}})
                            MERGE (ta)-[:HAS_FINDING]->(tf)
                            """,
                            asset_id=asset_id, finding_id=finding_id,
                            uid=user_id, pid=project_id,
                        )
                        stats["relationships_created"] += 1
                except Exception as e:
                    stats["errors"].append(f"Failed to create finding {dedup_key}: {e}")

            print(f"\n[+] TruffleHog Graph Update Summary ({source}):")
            print(f"[+][graph-db] Created {stats['scan_created']} MultiscannerScan node")
            print(f"[+][graph-db] Created {stats['assets_created']} {asset_label} nodes")
            print(f"[+][graph-db] Created {stats['findings_created']} MultiscannerFinding nodes")
            print(f"[+][graph-db] Created {stats['relationships_created']} relationships")
            print(f"[+][graph-db] Deduplicated {stats['findings_deduplicated']} findings")

            if stats["errors"]:
                print(f"[!][graph-db] {len(stats['errors'])} errors occurred")

        # X7: the clear above spares the findings a person touched, so this is
        # the only thing that ever marks one of them resolved when the secret is
        # gone. Scoped to THIS source id (`MultiscannerFinding.source`), so a
        # Docker run cannot touch HuggingFace findings. Only after an ingest
        # that wrote something: a run that wrote nothing is a failed scan.
        if stats["findings_created"]:
            stats["pruned"] = self.prune_unseen_findings(
                user_id, project_id, [source], run_started_at)

        return stats
