"""Finding triage: AI verdicts, and the mute / unmute suppression state.

Two separate things live here, and keeping them separate is the point:

- A **verdict** (`triage_status` and friends) is the classifier's opinion. It
  ranks a finding and never hides it, and the AI can write nothing else.
- A **mute** is a human decision to suppress a finding as noise. It adds the
  `:Muted` label, which makes the node invisible to every agent query and every
  analytics, report and graph read.

Only a person mutes. `apply_triage_verdicts` cannot set `:Muted` no matter what
the model returns, so a prompt injection in scanner output (`raw_response`,
`evidence`) can at worst mislabel a verdict a human can overrule.

See `docs/readmes/GRAPH.SCHEMA.md` for the label's schema contract, and
`graph_db/tenant_filter.py` for how invisibility is enforced.
"""

#: Labels a finding can be muted on. Asset and reference nodes (IP, Port,
#: Domain, Endpoint, CVE, ...) are deliberately absent: they are context, and
#: muting one would orphan the real findings hanging off it.
#:
#: Used as a Cypher label expression, so a node id that belongs to anything else
#: matches nothing and the write is a no-op. That is the fail-closed direction:
#: a caller cannot mute an asset by guessing its id.
#:
#: Keep in sync with MUTEABLE in `webapp/src/lib/muteEnforcement.test.ts`.
MUTEABLE_LABELS = (
    "Vulnerability",
    "JsReconFinding",
    "Secret",
    "MultiscannerFinding",
    "GithubSecret",
    "GithubSensitiveFile",
    "MalPackageFinding",
    "ExploitGvm",
)

_MUTEABLE = "|".join(MUTEABLE_LABELS)

#: Findings are keyed on `id`, except MalPackageFinding, whose uniqueness
#: constraint is on `finding_id` (`graph_db/schema.py`). Matching either keeps
#: one call site for all eight labels.
#:
#: This is the stored `id` PROPERTY and never Neo4j's elementId: import and
#: version-activate do DETACH DELETE and recreate, so elementId changes under a
#: node that is otherwise the same finding.
_BY_ID = "(n.id = $node_id OR n.finding_id = $node_id)"

#: The functional label of a muted node. A muted finding is dual-labelled and
#: Neo4j does not order labels, so `labels(n)[0]` may be 'Muted' and would
#: mis-type the row. Everything reporting "what kind of finding is this" uses
#: this instead.
_FUNCTIONAL_LABEL = "[l IN labels(n) WHERE l <> 'Muted'][0]"

#: Worst-first ordering, so a capped list keeps the findings that matter. An
#: unknown or missing severity sorts last rather than being treated as critical.
_SEVERITY_RANK = """CASE toLower(coalesce(n.severity, ''))
             WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2
             WHEN 'low' THEN 3 WHEN 'info' THEN 4 ELSE 5 END"""

#: Verdict + priority properties the triage phase owns. Listed once so the write
#: and the unmute cleanup cannot drift apart.
TRIAGE_PROPS = (
    "triage_status",
    "triage_confidence",
    "triage_reason",
    "triage_source",
    "triage_cluster_id",
    "triaged_at",
    # Prioritisation (deterministic scorer). triage_priority_score is THE sort
    # key: higher = more urgent. Deliberately no inverted "priority number".
    "triage_priority_score",
    "triage_signals",
)

VALID_TRIAGE_STATUS = ("confirmed", "likely_noise", "needs_verification", "unreviewed")


class TriageMixin:
    """Mute/unmute and AI-verdict writes for finding nodes."""

    def mute_finding(self, user_id: str, project_id: str, node_id: str,
                     muted_by: str = "", reason: str = "") -> dict:
        """Suppress one finding as noise.

        Adds `:Muted` ALONGSIDE the finding's own label rather than replacing it.
        That is what makes unmute lossless and what lets a re-scan keep the mute:
        recon re-runs `MERGE (v:Vulnerability {id, user_id, project_id})`, which
        still matches a `:Vulnerability:Muted` node, refreshes its scan
        properties and leaves the suppression intact. Relabelling would make that
        MERGE miss and create a second, un-muted duplicate.

        Idempotent: muting an already-muted finding refreshes nothing but the
        reason, and returns muted=True.

        Returns {"muted": bool, "label": str|None}. `muted=False` means nothing
        matched: a wrong id, another tenant's id, or an asset node, all of which
        are indistinguishable to the caller on purpose.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n:Muted,
            n.muted = true,
            n.muted_at = datetime(),
            n.muted_by = $muted_by,
            n.muted_reason = $reason
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query,
                node_id=node_id, user_id=user_id, project_id=project_id,
                muted_by=muted_by or user_id, reason=reason or "",
            ).single()

        if record is None:
            return {"muted": False, "label": None}
        return {"muted": True, "label": record["label"]}

    def unmute_finding(self, user_id: str, project_id: str, node_id: str) -> dict:
        """Restore a suppressed finding.

        Removes the label and the muted properties and touches nothing else, so
        the finding comes back with every relationship and scan property it had.
        Idempotent.

        Note this deliberately does NOT clear the triage verdict: unmuting is
        "show me this again", not "forget what we concluded about it".
        """
        query = f"""
        MATCH (n:Muted)
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        REMOVE n:Muted, n.muted, n.muted_at, n.muted_by, n.muted_reason
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id
            ).single()

        if record is None:
            return {"unmuted": False, "label": None}
        return {"unmuted": True, "label": record["label"]}

    def list_muted(self, user_id: str, project_id: str) -> list:
        """Every suppressed finding in the project.

        The ONLY query in the codebase that deliberately matches `:Muted`. It is
        reachable exclusively from the webapp's Muted-table endpoint over the
        internal API; the agent cannot reach it, and `scope_query` refuses any
        agent query that so much as names the label.
        """
        query = f"""
        MATCH (n:Muted)
        WHERE n.user_id = $user_id AND n.project_id = $project_id
        RETURN coalesce(n.id, n.finding_id)        AS id,
               {_FUNCTIONAL_LABEL}                 AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               toString(n.muted_at)                AS muted_at,
               coalesce(n.muted_by, '')            AS muted_by,
               coalesce(n.muted_reason, '')        AS muted_reason,
               coalesce(n.triage_status, 'unreviewed') AS triage_status,
               n.triage_reason                     AS triage_reason
        ORDER BY n.muted_at DESC
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(
                query, user_id=user_id, project_id=project_id)]

    def list_triage_findings(self, user_id: str, project_id: str, limit: int = 2000) -> list:
        """Every finding in triage scope that is NOT muted, for the Triage table.

        Carries the priority score + signals + verdict props so the table can
        rank and explain each row. Absent `triage_priority_score` sorts last
        (an un-scored finding, e.g. from before a run), so a fresh project is not
        mis-ranked. `count_triage_findings` gives the caller the true total so a
        capped list can say "showing N of M" -- and the cap now keeps the
        top-N by priority rather than an arbitrary subset, because the score is a
        near-total order.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        OPTIONAL MATCH (parent)-[:HAS_VULNERABILITY|FOUND_AT|HAS_SECRET|HAS_FINDING]-(n)
        WITH n, head(collect(parent)) AS parent
        RETURN coalesce(n.id, n.finding_id)        AS id,
               labels(n)[0]                        AS label,
               coalesce(n.name, n.detector_name, n.secret_type, n.type, '') AS name,
               coalesce(n.severity, '')            AS severity,
               coalesce(n.source, '')              AS source,
               coalesce(n.matched_at, n.url, n.endpoint, '') AS location,
               coalesce(parent.name, parent.address, parent.url, '') AS host,
               coalesce(n.triage_status, 'unreviewed') AS triage_status,
               n.triage_confidence                 AS triage_confidence,
               n.triage_reason                     AS triage_reason,
               coalesce(n.triage_source, '')       AS triage_source,
               n.triage_cluster_id                 AS triage_cluster_id,
               n.triage_priority_score             AS triage_priority_score,
               coalesce(n.triage_signals, [])      AS triage_signals,
               toString(n.updated_at)              AS updated_at
        ORDER BY coalesce(n.triage_priority_score, -1) DESC,
                 {_SEVERITY_RANK},
                 coalesce(n.id, n.finding_id)
        LIMIT $limit
        """
        with self.driver.session() as session:
            return [dict(r) for r in session.run(
                query, user_id=user_id, project_id=project_id, limit=limit)]

    def count_triage_findings(self, user_id: str, project_id: str) -> int:
        """How many findings are in triage scope, ignoring the display cap.

        The Triage table is capped, so this is what lets the UI say "showing N
        of M" instead of presenting a truncated list as the whole picture.
        """
        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE n.user_id = $user_id AND n.project_id = $project_id
          AND NOT n:Muted
        RETURN count(n) AS total
        """
        with self.driver.session() as session:
            record = session.run(
                query, user_id=user_id, project_id=project_id).single()
        return int(record["total"]) if record else 0

    def apply_triage_verdicts(self, user_id: str, project_id: str, verdicts: list) -> dict:
        """Write AI verdicts onto findings.

        `verdicts` is a list of {id, triage_status, triage_confidence,
        triage_reason, triage_cluster_id}.

        Two guarantees this method is responsible for, both enforced in Cypher
        rather than trusted to the caller:

        1. **A human verdict is never overwritten.** `triage_source = 'human'`
           means someone already decided; a re-run must leave it alone, or the
           operator's judgement silently evaporates on the next triage.
        2. **The classifier cannot mute.** There is no `SET n:Muted` here and
           there must never be one. Scanner output reaches the classify prompt,
           so a model that has been talked into saying "hide me" can at worst
           write a verdict a human can see and overrule.

        Unknown statuses are dropped rather than written, so a malformed model
        response cannot invent a state the UI has no meaning for.
        """
        clean = []
        for v in verdicts or []:
            node_id = (v or {}).get("id")
            status = (v or {}).get("triage_status")
            if not node_id or status not in VALID_TRIAGE_STATUS:
                continue
            confidence = v.get("triage_confidence")
            try:
                confidence = max(0.0, min(1.0, float(confidence)))
            except (TypeError, ValueError):
                confidence = None
            clean.append({
                "id": str(node_id),
                "status": status,
                "confidence": confidence,
                "reason": str(v.get("triage_reason") or "")[:500],
                "cluster_id": str(v.get("triage_cluster_id") or "") or None,
            })

        if not clean:
            return {"updated": 0, "skipped_human": 0, "rejected": len(verdicts or [])}

        query = f"""
        UNWIND $verdicts AS verdict
        MATCH (n:{_MUTEABLE})
        WHERE (n.id = verdict.id OR n.finding_id = verdict.id)
          AND n.user_id = $user_id AND n.project_id = $project_id
        WITH n, verdict, n.triage_source = 'human' AS isHuman
        FOREACH (_ IN CASE WHEN isHuman THEN [] ELSE [1] END |
          SET n.triage_status     = verdict.status,
              n.triage_confidence = verdict.confidence,
              n.triage_reason     = verdict.reason,
              n.triage_cluster_id = verdict.cluster_id,
              n.triage_source     = 'ai',
              n.triaged_at        = datetime()
        )
        RETURN count(CASE WHEN isHuman THEN 1 END) AS skipped_human,
               count(CASE WHEN isHuman THEN NULL ELSE 1 END) AS updated
        """
        with self.driver.session() as session:
            record = session.run(
                query, verdicts=clean, user_id=user_id, project_id=project_id
            ).single()

        return {
            "updated": (record["updated"] if record else 0) or 0,
            "skipped_human": (record["skipped_human"] if record else 0) or 0,
            "rejected": len(verdicts or []) - len(clean),
        }

    def apply_triage_scores(self, user_id: str, project_id: str, rows: list) -> dict:
        """Write the deterministic priority score onto findings.

        `rows` is a list of {id, score, signals, status?, confidence?} produced by
        the scorer. This is the ranking backbone: `triage_priority_score` (higher
        = more urgent) is the table's sort key, `triage_signals` is the
        transparent "why it ranked here", and `triage_status`/`triage_confidence`
        are set ONLY when the graph is decisive (the scorer's auto-verdict) —
        never a guess.

        Same two guarantees as `apply_triage_verdicts`, enforced in Cypher:
        a `triage_source = 'human'` finding is never overwritten, and there is no
        `SET n:Muted` here and never must be. The score is deterministic, so a
        re-run is idempotent for AI-owned findings.
        """
        clean = []
        for r in rows or []:
            node_id = (r or {}).get("id")
            if not node_id:
                continue
            try:
                score = float(r.get("score"))
            except (TypeError, ValueError):
                score = 0.0
            signals = r.get("signals") or []
            if not isinstance(signals, list):
                signals = [str(signals)]
            status = r.get("status")
            if status not in VALID_TRIAGE_STATUS:
                status = None            # leave the verdict untouched when not decisive
            confidence = r.get("confidence")
            try:
                confidence = None if confidence is None else max(0.0, min(1.0, float(confidence)))
            except (TypeError, ValueError):
                confidence = None
            clean.append({
                "id": str(node_id),
                "score": score,
                "signals": [str(s) for s in signals],
                "status": status,
                "confidence": confidence,
                "reason": str(r.get("reason") or "")[:500] or None,
                "cluster_id": str(r.get("cluster_id") or "") or None,
            })

        if not clean:
            return {"updated": 0, "skipped_human": 0, "rejected": len(rows or [])}

        # The score/signals always write (they are deterministic and carry no
        # opinion). The verdict fields write only when the row supplies a
        # decisive status, so an ambiguous finding awaiting the LLM rationale is
        # ranked now and keeps whatever verdict it had.
        query = f"""
        UNWIND $rows AS row
        MATCH (n:{_MUTEABLE})
        WHERE (n.id = row.id OR n.finding_id = row.id)
          AND n.user_id = $user_id AND n.project_id = $project_id
        WITH n, row, n.triage_source = 'human' AS isHuman
        FOREACH (_ IN CASE WHEN isHuman THEN [] ELSE [1] END |
          SET n.triage_priority_score = row.score,
              n.triage_signals        = row.signals,
              n.triaged_at            = datetime(),
              n.triage_source         = 'ai'
        )
        FOREACH (_ IN CASE WHEN isHuman OR row.status IS NULL THEN [] ELSE [1] END |
          SET n.triage_status     = row.status,
              n.triage_confidence  = row.confidence
        )
        FOREACH (_ IN CASE WHEN isHuman OR row.reason IS NULL THEN [] ELSE [1] END |
          SET n.triage_reason = row.reason)
        FOREACH (_ IN CASE WHEN isHuman OR row.cluster_id IS NULL THEN [] ELSE [1] END |
          SET n.triage_cluster_id = row.cluster_id)
        RETURN count(CASE WHEN isHuman THEN 1 END) AS skipped_human,
               count(CASE WHEN isHuman THEN NULL ELSE 1 END) AS updated
        """
        with self.driver.session() as session:
            record = session.run(
                query, rows=clean, user_id=user_id, project_id=project_id
            ).single()

        return {
            "updated": (record["updated"] if record else 0) or 0,
            "skipped_human": (record["skipped_human"] if record else 0) or 0,
            "rejected": len(rows or []) - len(clean),
        }

    def set_human_verdict(self, user_id: str, project_id: str, node_id: str,
                          status: str, reason: str = "") -> dict:
        """Record an operator's own verdict, which the AI may not later overwrite.

        Stamping `triage_source = 'human'` is what makes the skip in
        `apply_triage_verdicts` fire on the next run.
        """
        if status not in VALID_TRIAGE_STATUS:
            return {"updated": False, "reason": f"invalid status {status!r}"}

        query = f"""
        MATCH (n:{_MUTEABLE})
        WHERE {_BY_ID} AND n.user_id = $user_id AND n.project_id = $project_id
        SET n.triage_status = $status,
            n.triage_reason = $reason,
            n.triage_source = 'human',
            n.triage_confidence = 1.0,
            n.triaged_at = datetime()
        RETURN {_FUNCTIONAL_LABEL} AS label
        """
        with self.driver.session() as session:
            record = session.run(
                query, node_id=node_id, user_id=user_id, project_id=project_id,
                status=status, reason=str(reason or "")[:500],
            ).single()

        return {"updated": record is not None,
                "label": record["label"] if record else None}
