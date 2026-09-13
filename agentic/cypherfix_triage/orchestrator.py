"""Hybrid triage orchestrator: static Cypher collection + ReAct LLM analysis."""

import asyncio
import json
import logging
import os
import re
from typing import Optional

import httpx

from cypherfix_errors import safe_error
from prompt_safety import wrap_untrusted
from .state import TriageState, TriageFinding, RemediationDraft
from .tools import TriageNeo4jToolManager
from . import evidence, grouping, remediation, score_model
from .prompts import remediation_prose, review
from .prompts.review import validate_review
from .fact_queries import (
    FINDING_QUERIES,
    PROJECT_FACT_QUERIES,
    build_project_facts,
    normalise_finding_row,
)
from .intel import CveIntel
from .run_client import TriageRunAborted, TriageRunClient
from .project_settings import load_cypherfix_settings

logger = logging.getLogger(__name__)

WEBAPP_API_URL = os.environ.get("WEBAPP_API_URL", "http://webapp:3000")
INTERNAL_HEADERS = {"X-Internal-Key": os.environ.get("INTERNAL_API_KEY", "")}

#: Step C limits. The wall clock matters more than the batch sizes: a provider
#: having a bad afternoon must cost detail, never the whole ranking, so findings
#: the budget does not reach publish as "not reviewed" with their maths intact.
REVIEW_BATCH_SIZE = 12
REVIEW_BATCH_CHARS = 30000
REVIEW_BUDGET_SECONDS = 20 * 60


class TriageOrchestrator:
    """One triage run: score, group, review, remediate, publish.

    THE SHAPE THAT MATTERS. Steps A to D happen entirely in memory; Step E is
    the only thing that writes. That is what makes a run safe to stop, safe to
    refuse and safe to run beside a scan: until the publish is claimed, the
    previous ranking is still what an operator sees, and a run that is killed
    halfway has changed nothing at all.

      [R] authorize   ask the webapp for a run, before reading anything
      [A] score       fact sets + one row per finding -> score_model (no LLM)
      [B] group       findings that share a fix (deterministic keys)
      [C] review      the LLM corrects factors against quoted evidence
      [D] remediate   one remediation per group
      [E] publish     claim, write the graph in batches, upsert, finish
    """

    def __init__(self, user_id: str, project_id: str, callback,
                 real_actor_user_id: str | None = None):
        self.user_id = user_id
        self.project_id = project_id
        self.callback = callback
        self.real_actor_user_id = real_actor_user_id
        self.neo4j = TriageNeo4jToolManager(user_id, project_id)
        self.llm_client = None
        self.run_client: TriageRunClient | None = None
        self.facts = None
        self.groups: dict = {}
        self.remediation_rows: list = []
        self.intel: dict = {}
        self.intel_date: str = ""
        self._client = None         # one Neo4jClient per run (K26, X17)

    async def run(self, state: TriageState) -> TriageState:
        """Authorise, work in memory, publish once, always record the outcome."""
        summary: dict = {}
        status = "failed"
        error_class = ""

        settings = await load_cypherfix_settings(self.project_id)
        state["settings"] = settings
        # `llm_model` is the key load_cypherfix_settings actually returns.
        # Reading "model" silently yielded "" everywhere it was used: the
        # run recorded no model, every reviewed finding recorded no model,
        # and the review cache key omitted it, so switching models reused
        # the previous one's verdicts.
        model = str(settings.get("llm_model") or "")

        self.run_client = TriageRunClient(
            self.project_id, self.user_id, self.real_actor_user_id)

        try:
            # [R] AUTHORIZE. Before any read: a run that is not allowed to
            # publish must not spend minutes and LLM budget discovering that.
            await self.callback.on_phase("authorizing", "Checking the project...", 2)
            await self.run_client.authorize(model, score_model.SCORE_MODEL_VERSION)
            self.run_client.start_heartbeat()

            # [A] SCORE. Deterministic, no LLM, nothing written.
            await self.callback.on_phase("scoring", "Scoring findings...", 10)
            scored = await self._score(state)
            state["verdicts"] = scored
            summary["scored"] = len(scored)
            self.run_client.check_abort()

            if not scored:
                await self._publish_nothing()
                status = "completed"
                await self.callback.on_complete(
                    0, {}, {}, "No findings in scope for this project.")
                state["status"] = "complete"
                return state

            # The LLM is set up only AFTER scoring, so a project with no
            # provider key still gets a fully ranked board (C15). The old order
            # raised here and left nothing scored at all.
            self.llm_client = await self._init_llm_or_none(settings)
            summary["llm_available"] = 1 if self.llm_client else 0

            # [B] GROUP, [C] REVIEW, [D] REMEDIATE.
            scored = await self._group(scored)
            summary["groups"] = len({r.get("group_key") for r in scored
                                     if r.get("group_key")})
            self.run_client.check_abort()

            review_summary = await self._review(state, scored)
            summary.update(review_summary)
            self.run_client.check_abort()

            analysis = await self._remediate(state, scored)
            state["analysis_result"] = analysis

            # [E] PUBLISH. Claim first: a run that lost its claim writes nothing.
            await self.callback.on_phase("publishing", "Publishing results...", 92)
            await self.run_client.claim_publish()
            written = await self._publish(scored, self.run_client.run_id or "")
            summary["nodes_written"] = written["updated"]
            summary["skipped_changed"] = written["skipped_changed"]

            saved = await self._save_remediations(analysis, self.run_client.run_id or "")
            summary.update(saved or {})

            status = "completed_partial" if self.run_client.aborted else "completed"
            await self.callback.on_complete(
                total=analysis.count,
                by_severity=analysis.by_severity,
                by_type=analysis.by_type,
                summary=analysis.summary,
            )
            state["status"] = "complete"
            return state

        except TriageRunAborted as aborted:
            status = "stopped" if aborted.error_class == "stopped" else "failed"
            error_class = aborted.error_class
            logger.warning(f"Triage run ended early: {aborted.reason}")
            await self.callback.on_error(
                safe_error(aborted.error_class), recoverable=True,
                code=aborted.error_class)
            state["status"] = "error"
            state["error"] = aborted.error_class
            return state

        finally:
            # Always, including after an exception: a run left `running` blocks
            # activation until its heartbeat expires ten minutes later.
            try:
                if self.run_client is not None:
                    await self.run_client.finish(status, summary, error_class,
                                          self.intel_date)
            finally:
                self._close_graph_client()
                try:
                    await self.neo4j.close()
                except Exception:                                 # noqa: BLE001
                    pass
                self._log_run_event(status, summary, error_class)

    async def _publish_nothing(self) -> None:
        """An empty project still finishes cleanly through the protocol."""
        try:
            await self.run_client.claim_publish()
        except TriageRunAborted:
            pass

    def _log_run_event(self, status: str, summary: dict, error_class: str) -> None:
        """One telemetry line per run, on EVERY terminal state (D4).

        The old event fired after a successful save and also after a swallowed
        failure, and never at all on the empty-graph return or on a raised
        error, so the numbers could not be read as "what happened".
        """
        try:
            from session_log import log_event
            log_event(
                "triage_run",
                user_id=self.user_id, project_id=self.project_id,
                run_id=(self.run_client.run_id if self.run_client else "") or "",
                status=status, error_class=error_class,
                model_version=score_model.SCORE_MODEL_VERSION,
                **{k: v for k, v in (summary or {}).items()
                   if isinstance(v, (int, float))},
            )
        except Exception:                                         # noqa: BLE001
            pass

    async def _init_llm_or_none(self, settings: dict):
        """The LLM, or None. Never raises.

        A missing provider key used to raise BEFORE scoring, so a project with
        no key got no ranking at all while the documentation promised the
        opposite (C15). The ranking is deterministic and does not need a model;
        only the review and the remediation prose do.
        """
        try:
            return await self._init_llm(settings)
        except Exception as e:                                    # noqa: BLE001
            logger.warning(
                f"No usable LLM for this run ({e.__class__.__name__}); "
                f"publishing the math-only ranking")
            return None

    # ── Step B: group by "what the fix is" ────────────────────────────────

    async def _group(self, scored: list) -> list:
        """Stamp a deterministic group key on every finding.

        No LLM. The old cluster call produced `triage_cluster_id`, which the UI
        never read, could not be verified in code, and grouped the same graph
        differently on two runs.
        """
        await self.callback.on_phase("grouping", "Grouping findings by fix...", 30)
        groups = grouping.assign_groups(scored)
        self.groups = groups

        # A group's score is shared by its members, so the board can collapse a
        # group into one row without its rank changing.
        for group in groups.values():
            for member in group["members"]:
                member["group_score"] = group["score"]
                member["group_tier"] = group["tier"]
                member["group_size"] = len(group["members"])
                member["group_members"] = [
                    {"id": m["id"], "name": m.get("name")} for m in group["members"]
                ]

        logger.info(f"Grouped {len(scored)} findings into {len(groups)} groups")
        return scored

    # ── Step C: the evidence review ───────────────────────────────────────

    async def _review(self, state: TriageState, scored: list) -> dict:
        """Let the model correct the factors, and verify every word of it.

        Budgeted, cached and concurrent. Findings the budget or the clock does
        not reach publish as "not reviewed" with their maths intact, which is
        the difference between a slow provider costing detail and costing the
        whole ranking.
        """
        summary = {"reviewed": 0, "cache_hits": 0, "not_reviewed": 0,
                   "false_positives": 0, "llm_calls": 0}
        settings = state.get("settings", {}) or {}
        budget = int(settings.get("triageReviewBudget", 150) or 0)

        candidates = [r for r in scored if evidence.should_review(r)]
        for row in scored:
            if row not in candidates:
                row["ai_verdict"] = None

        if not self.llm_client or budget <= 0 or not candidates:
            for row in candidates:
                row["ai_verdict"] = "not_reviewed"
            summary["not_reviewed"] = len(candidates)
            if candidates:
                logger.info(f"Review skipped for {len(candidates)} findings "
                            f"(no model or budget 0); the ranking still publishes")
            return summary

        # Highest group score first, so a budget that runs out runs out on the
        # findings that matter least.
        candidates.sort(key=lambda r: (-float(r.get("group_score") or r["score"]),
                                       str(r["id"])))
        candidates = candidates[:budget]
        # `llm_model` is the key load_cypherfix_settings actually returns.
        # Reading "model" silently yielded "" everywhere it was used: the
        # run recorded no model, every reviewed finding recorded no model,
        # and the review cache key omitted it, so switching models reused
        # the previous one's verdicts.
        model = str(settings.get("llm_model") or "")

        pending = []
        for row in candidates:
            bundle = evidence.build_bundle(row.get("_row") or row)
            row["_bundle"] = bundle
            new_hash = evidence.evidence_hash(
                bundle, review.REVIEW_PROMPT_VERSION, model)
            if new_hash and new_hash == row.get("evidence_hash"):
                # Nothing about this finding or this prompt has changed since
                # the last run, so the stored verdict still answers the question.
                summary["cache_hits"] += 1
                row["ai_verdict"] = row.get("ai_verdict") or "unclear"
                continue
            row["evidence_hash"] = new_hash
            pending.append(row)

        if not pending:
            logger.info(f"Review: all {summary['cache_hits']} findings were cached")
            return summary

        await self.callback.on_phase(
            "reviewing", f"Reviewing evidence (0/{len(pending)})...", 45)

        batches = self._review_batches(pending)
        semaphore = asyncio.Semaphore(3)
        deadline = asyncio.get_event_loop().time() + REVIEW_BUDGET_SECONDS
        reviewed_ids: set = set()

        async def run_batch(batch, index):
            if asyncio.get_event_loop().time() > deadline:
                return {}
            async with semaphore:
                summary["llm_calls"] += 1
                answers = await self._review_batch(batch, model)
                done = min(len(pending), (index + 1) * REVIEW_BATCH_SIZE)
                await self.callback.on_phase(
                    "reviewing", f"Reviewing evidence ({done}/{len(pending)})...",
                    45 + int(30 * done / max(1, len(pending))))
                return answers

        results = await asyncio.gather(
            *[run_batch(batch, i) for i, batch in enumerate(batches)],
            return_exceptions=True)

        by_id = {}
        for result in results:
            if isinstance(result, dict):
                by_id.update(result)

        for row in pending:
            answer = by_id.get(row["id"])
            if not answer:
                row["ai_verdict"] = "not_reviewed"
                continue
            reviewed_ids.add(row["id"])
            self._apply_review(row, answer)
            if row.get("ai_verdict") == "false_positive":
                summary["false_positives"] += 1

        summary["reviewed"] = len(reviewed_ids)
        summary["not_reviewed"] = len(pending) - len(reviewed_ids)
        logger.info(f"Review: {summary}")
        return summary

    @staticmethod
    def _review_batches(rows: list) -> list:
        """Batches of about 12 findings, capped by characters as well as count.

        Grouped members stay together where they fit, so the model sees "this
        CVE, on these three hosts" rather than three unrelated-looking findings.
        """
        batches, current, size = [], [], 0
        for row in rows:
            cost = len(row.get("_bundle") or "") + 600
            if current and (len(current) >= REVIEW_BATCH_SIZE
                            or size + cost > REVIEW_BATCH_CHARS):
                batches.append(current)
                current, size = [], 0
            current.append(row)
            size += cost
        if current:
            batches.append(current)
        return batches

    async def _review_batch(self, batch: list, model: str) -> dict:
        """One call, with no tools bound. Returns {id: validated answer}."""
        rendered = "\n".join(
            review.render_finding(row, row.get("_bundle") or "") for row in batch)
        payload = wrap_untrusted(rendered, "FINDINGS_AND_EVIDENCE")
        asked = {row["id"]: row for row in batch}

        try:
            response = await self._call_llm(
                review.REVIEW_SYSTEM_PROMPT,
                [{"role": "user", "content": review.build_review_prompt(payload)}],
            )
        except Exception as e:                                    # noqa: BLE001
            logger.warning(f"Review batch failed ({e.__class__.__name__}); "
                           f"{len(batch)} findings stay math-only")
            return {}

        answers = {}
        for item in self._extract_json_array(self._response_text(response)):
            if not isinstance(item, dict):
                continue
            finding_id = str(item.get("id", ""))
            row = asked.get(finding_id)
            if row is None:
                continue                # an id we did not ask about
            validated = validate_review(item, row.get("_bundle") or "", row)
            if validated:
                validated["model"] = model
                answers[finding_id] = validated
        return answers

    def _apply_review(self, row: dict, answer: dict) -> None:
        """Re-run the rules with the AI's accepted corrections.

        The AI moved factors; the tier and the score come from the same rules
        that produced them in the first place, so it can never place a finding
        somewhere the facts do not support.
        """
        factors = row.get("factors") or {}
        c = float((factors.get("C") or {}).get("value") or 0.0)
        l = float((factors.get("L") or {}).get("value") or 0.0)
        i = float((factors.get("I") or {}).get("value") or 0.0)
        r = float((factors.get("R") or {}).get("value") or 0.0)

        verdict = answer["verdict"]
        if verdict == "real":
            c = max(c, 0.95)
        elif verdict == "doubtful":
            c = min(c, 0.25)

        for dispute in answer["disputed_facts"]:
            fact = dispute["fact"]
            if fact == "reachable":
                r = score_model.REACH_UNKNOWN
            elif fact in ("tool_confirmed", "extracted_proof"):
                c = min(c, 0.75)
            elif fact in ("dast_confirmed", "exploitable_class"):
                l = min(l, 0.3)
            elif fact == "public_poc":
                l = min(l, 0.3)
            elif fact == "sensitive_asset":
                i = i / 1.2
            elif fact == "credential_in_response":
                l = min(l, 0.3)

        i = min(1.2, max(0.0, i * answer["impact_multiplier"]))

        row["ai_verdict"] = verdict
        row["ai_quote"] = answer["evidence_quote"]
        row["ai_model"] = answer.get("model", "")
        row["ai_corrections"] = {
            "verdict": verdict,
            "impact_multiplier": answer["impact_multiplier"],
            "disputed_facts": answer["disputed_facts"],
            "before": {"C": c, "L": l, "I": i, "R": r},
        }
        row["reason"] = answer["why"] or None
        row["fix_lever"] = answer["fix_lever"] or None

        if verdict == "false_positive":
            # NEVER muted: it moves to its own section, one click from Real.
            row["state"] = score_model.STATE_FALSE_POSITIVE
            row["status"] = "likely_noise"
            row["score"] = 0.0
            row["risk"] = 0.0
            return

        factors["C"] = {"value": round(c, 4),
                        "evidence": (factors.get("C") or {}).get("evidence", "")}
        factors["L"] = {"value": round(l, 4),
                        "evidence": (factors.get("L") or {}).get("evidence", "")}
        factors["I"] = {"value": round(i, 4),
                        "evidence": (factors.get("I") or {}).get("evidence", "")}
        factors["R"] = {"value": round(r, 4),
                        "evidence": (factors.get("R") or {}).get("evidence", "")}
        row["factors"] = factors

        source_row = row.get("_row") or {}
        risk = min(1.0, c * l * i * r)
        tier, tier_rule = score_model.tier_for(
            source_row, self.facts or score_model.ProjectFacts(), self.intel,
            c, l, i, r)
        row["risk"] = round(risk, 6)
        row["tier"] = tier
        row["tier_rule"] = tier_rule
        row["score"] = score_model.score_for(tier, risk)

    # ── Step A: score every finding, in memory ────────────────────────────

    async def _score(self, state: TriageState) -> list:
        """Read the graph and score it. Writes NOTHING.

        Two reads, in this order:

        1. the project fact sets, once. Which hosts are live, which ports an
           active scan found, which packages are actually served, what the agent
           proved. Small, and shared by every finding.
        2. one row per finding. `COUNT {}` / `EXISTS {}` subqueries rather than
           OPTIONAL MATCH chains, so a GVM finding with three Technology parents
           is one row and not five (C5), and one OSV advisory hanging off eleven
           packages is one row and not eleven.

        Then `score_model.score` joins them, purely. Nothing reaches the graph
        until Step E, so a run that is stopped or refused halfway leaves the
        previous ranking exactly as it was.

        Never raises on a per-query failure: a fact set that fails to load stays
        empty, which the model reads as "unknown", never as "false".
        """
        raw_facts = {}
        for query_def in PROJECT_FACT_QUERIES:
            try:
                raw_facts[query_def["name"]] = await self.neo4j.run_static_query(
                    query_def["query"])
            except Exception as e:
                logger.error(f"Fact query {query_def['name']!r} failed "
                             f"(treated as unknown): {e}")
                raw_facts[query_def["name"]] = []
        facts = build_project_facts(raw_facts)
        self.facts = facts
        logger.info(
            f"Facts: {len(facts.live_hosts)} live hosts, "
            f"{len(facts.port_hosts)} hosts with open ports, "
            f"{len(facts.package_exposure)} packages, "
            f"{len(facts.proven_cve_ids)} proven CVEs, "
            f"{len(facts.compromised_hosts)} compromised hosts")

        rows: list = []
        for query_def in FINDING_QUERIES:
            try:
                found = await self.neo4j.run_static_query(query_def["query"])
            except Exception as e:
                logger.error(f"Finding query {query_def['name']!r} failed: {e}")
                continue
            for row in found or []:
                if not isinstance(row, dict) or not row.get("id"):
                    continue
                rows.append(normalise_finding_row(row))

        if not rows:
            logger.info("Scoring: no findings in scope")
            return []

        await self._load_intel(rows, state)
        intel = self.intel or {}
        scored: list = []
        unknown_sources = set()
        for row in rows:
            result = score_model.score(row, facts, intel)
            for warning in result.warnings:
                unknown_sources.add(warning)
            scored.append({
                "id": str(row["id"]),
                "label": row.get("label") or "",
                "name": row.get("name") or "",
                "severity": row.get("severity") or "",
                "source": row.get("source") or "",
                # Phase 8a: the detector this operator's clicks are attached to.
                "detector": score_model.detector_key(row),
                "host": result.host,
                "state": result.state,
                "tier": result.tier,
                "tier_rule": result.tier_rule,
                "score": result.score,
                "math_score": result.score,
                "risk": result.risk,
                "factors": result.as_factors_dict(),
                "signals": result.signals,
                "proven": result.proven,
                "explanation": result.explanation,
                "seen_updated_at": row.get("seen_updated_at"),
                "evidence_hash": row.get("triage_evidence_hash"),
                "triage_status": row.get("triage_status"),
                "triage_source": row.get("triage_source"),
                "proof": facts.proof_by_host.get(result.host) or None,
                "model_version": score_model.SCORE_MODEL_VERSION,
                "_row": row,
            })

        for warning in sorted(unknown_sources):
            logger.warning(f"Score model: {warning}")

        scored.sort(key=lambda r: (-r["score"], str(r.get("severity")), r["id"]))
        for index, row in enumerate(scored, start=1):
            row["rank"] = index

        by_tier = {}
        for row in scored:
            by_tier[row["tier"]] = by_tier.get(row["tier"], 0) + 1
        logger.info(f"Scored {len(scored)} findings: {by_tier}")
        return scored

    async def _load_intel(self, rows: list, state: TriageState) -> None:
        """KEV, EPSS and public-PoC status for the CVEs in scope.

        Without it, "how likely is this to be exploited" falls back to a class
        prior and the CVSS vector, which cannot tell a CVE being exploited in
        the wild this week from one nobody has ever used.

        Only CVE ids leave the machine, and only after a regex check. Failure is
        not an error: the ranking degrades to the priors, which is the
        documented behaviour.
        """
        cve_ids = {c for row in rows for c in (row.get("cve_ids") or [])}
        if not cve_ids:
            return
        try:
            settings = state.get("settings", {}) or {}
            user_settings = settings.get("user_settings", {}) or {}
            loader = CveIntel(pdcp_api_key=user_settings.get("pdcpApiKey", ""))
            self.intel = await loader.load(cve_ids, self._graph_client())
            self.intel_date = loader.intel_date
            if loader.refreshed:
                logger.info(f"CVE intelligence: {loader.refreshed} refreshed, "
                            f"{len(self.intel)} known")
        except Exception as e:                                    # noqa: BLE001
            logger.warning(f"CVE intelligence unavailable ({e.__class__.__name__}); "
                           f"the ranking uses class priors")

    # ── Step E: publish, the only step that writes ────────────────────────

    async def _publish(self, scored: list, run_id: str) -> dict:
        """Write the ranking back, in batches, guarded by each node's updated_at.

        A node a scan re-ingested while this run was working is skipped: its
        facts are no longer the ones that were scored. It keeps its previous
        triage state and the next run picks it up.
        """
        totals = {"updated": 0, "skipped_human": 0, "skipped_changed": 0,
                  "rejected": 0}
        if not scored:
            return totals

        rows = [{
            "id": row["id"],
            "score": row["score"],
            "math_score": row.get("math_score", row["score"]),
            "risk": row.get("risk"),
            "signals": row.get("signals") or [],
            "state": row.get("state"),
            "tier": row.get("tier"),
            "tier_rule": row.get("tier_rule"),
            "factors": row.get("factors"),
            "host": row.get("host"),
            "group_key": row.get("group_key"),
            "detector": row.get("detector"),
            "run_id": run_id,
            "model_version": row.get("model_version"),
            "intel_date": self.intel_date,
            "proof": row.get("proof"),
            "evidence_hash": row.get("evidence_hash"),
            "fix_lever": row.get("fix_lever"),
            "status": row.get("status"),
            "confidence": row.get("confidence"),
            "reason": row.get("reason"),
            "ai_verdict": row.get("ai_verdict"),
            "ai_corrections": row.get("ai_corrections"),
            "ai_quote": row.get("ai_quote"),
            "ai_model": row.get("ai_model"),
            "seen_updated_at": row.get("seen_updated_at"),
        } for row in scored]

        # Batches of 500: one 5,000-row UNWIND is a single long transaction that
        # holds locks across the whole publish, and a Stop mid-way would then
        # roll back everything rather than leaving a consistent prefix.
        client = self._graph_client()
        for start in range(0, len(rows), 500):
            batch = rows[start:start + 500]
            try:
                result = await asyncio.to_thread(
                    client.apply_triage_scores, self.user_id, self.project_id, batch)
            except Exception as e:
                logger.error(f"Publish batch at {start} failed: {e}")
                continue
            for key in totals:
                totals[key] += int(result.get(key) or 0)

        logger.info(f"Published: {totals}")
        return totals

    def _graph_client(self):
        """One Neo4jClient per run.

        `BaseMixin.__init__` re-runs the whole schema DDL, and triage used to
        build a client per write: on a live stack that made each write build and
        abandon a Bolt connection pool and re-issue every constraint (K26, X17).
        """
        if self._client is None:
            from graph_db.neo4j_client import Neo4jClient
            self._client = Neo4jClient()
        return self._client

    def _close_graph_client(self) -> None:
        client, self._client = self._client, None
        if client is not None:
            try:
                client.close()
            except Exception as e:                                # noqa: BLE001
                logger.warning(f"Could not close the triage graph client: {e}")

    @staticmethod
    def _response_text(response) -> str:
        """Flatten a _call_llm result into plain text.

        The result carries a `content` LIST of {"type": "text", "text": ...}
        blocks, never a top-level "text" key.
        """
        if isinstance(response, dict):
            content = response.get("content", "")
        else:
            content = response
        if isinstance(content, list):
            out = []
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    out.append(block.get("text", ""))
                elif isinstance(block, str):
                    out.append(block)
            return "".join(out)
        return str(content or "")

    @staticmethod
    def _extract_json_array(text: str) -> list:
        """Pull the JSON array out of a fenced model response, or return []."""
        if not text:
            return []
        match = re.search(r"```(?:json)?\s*(\[.*?\])\s*```", text, re.DOTALL)
        raw = match.group(1) if match else None
        if raw is None:
            start, end = text.find("["), text.rfind("]")
            raw = text[start:end + 1] if 0 <= start < end else None
        if not raw:
            return []
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError:
            return []
        return parsed if isinstance(parsed, list) else []

    # ── Step D: one remediation per group ─────────────────────────────────

    async def _remediate(self, state: TriageState, scored: list) -> RemediationDraft:
        """Build the fix list from the groups, in board order.

        Every field that decides anything is computed in code; the model writes
        only the words, in batches, with no tools bound. With no model the prose
        is deterministic, so the fix list is never empty just because a provider
        is down.
        """
        settings = state.get("settings", {}) or {}
        ordered = grouping.ordered_groups(self.groups)
        eligible = remediation.eligible_groups(ordered)

        if not eligible:
            self.remediation_rows = []
            return RemediationDraft(summary="No findings need a fix item.")

        await self.callback.on_phase(
            "writing_remediations",
            f"Writing fix items (0/{len(eligible)})...", 78)

        target_repo = str(settings.get("default_repo") or "")
        target_branch = str(settings.get("default_branch") or "main")
        run_id = (self.run_client.run_id if self.run_client else "") or ""

        computed = [
            remediation.build_remediation(group, rank, run_id,
                                          target_repo, target_branch)
            for rank, group in enumerate(eligible, start=1)
        ]

        prose_by_key = await self._write_prose(eligible, computed)
        for index, (row, group) in enumerate(zip(computed, eligible)):
            prose = prose_by_key.get(row["groupKey"])
            if prose:
                computed[index] = remediation.build_remediation(
                    group, row["priority"], run_id, target_repo, target_branch,
                    prose=prose)

        self.remediation_rows = computed

        by_severity: dict = {}
        by_type: dict = {}
        for row in computed:
            by_severity[row["severity"]] = by_severity.get(row["severity"], 0) + 1
            by_type[row["category"]] = by_type.get(row["category"], 0) + 1

        return RemediationDraft(
            computed=computed, by_severity=by_severity, by_type=by_type,
            summary=f"{len(computed)} fix items across "
                    f"{sum(r['affectedAssetCount'] for r in computed)} assets.",
        )

    async def _write_prose(self, groups: list, computed: list) -> dict:
        """The model's half of Step D: title, description, solution, enums."""
        if not self.llm_client:
            logger.info("No model: the fix items use the standard wording")
            return {}

        by_key = {row["groupKey"]: row for row in computed}
        size = remediation_prose.PROSE_BATCH_SIZE
        batches = [groups[i:i + size] for i in range(0, len(groups), size)]
        semaphore = asyncio.Semaphore(3)

        async def run_batch(batch, index):
            rendered = "\n".join(
                remediation_prose.render_group(group, by_key[group["key"]])
                for group in batch if group["key"] in by_key)
            payload = wrap_untrusted(rendered, "FINDING_GROUPS")
            async with semaphore:
                try:
                    response = await self._call_llm(
                        remediation_prose.REMEDIATION_PROSE_SYSTEM_PROMPT,
                        [{"role": "user",
                          "content": remediation_prose.build_prose_prompt(payload)}],
                    )
                except Exception as e:                            # noqa: BLE001
                    logger.warning(
                        f"Fix-item wording failed for batch {index} "
                        f"({e.__class__.__name__}); using the standard text")
                    return {}
            done = min(len(groups), (index + 1) * size)
            await self.callback.on_phase(
                "writing_remediations",
                f"Writing fix items ({done}/{len(groups)})...",
                78 + int(12 * done / max(1, len(groups))))
            asked = {group["key"] for group in batch}
            out = {}
            for item in self._extract_json_array(self._response_text(response)):
                validated = remediation_prose.validate_prose(item)
                if validated and validated["groupKey"] in asked:
                    out[validated["groupKey"]] = validated
            return out

        results: dict = {}
        for result in await asyncio.gather(
                *[run_batch(batch, i) for i, batch in enumerate(batches)],
                return_exceptions=True):
            if isinstance(result, dict):
                results.update(result)
        return results

    async def _save_remediations(self, analysis: RemediationDraft,
                                 run_id: str) -> dict:
        """Upsert the fix list by (project, group key), in one transaction.

        The old path DELETED every pending remediation and then created the new
        ones, outside a transaction: a failure in between left the project with
        no fix list at all, and a row the CodeFix agent was working on could be
        deleted underneath it.
        """
        rows = analysis.computed
        if not rows:
            return {}

        try:
            async with httpx.AsyncClient(timeout=60.0) as client:
                response = await client.post(
                    f"{WEBAPP_API_URL}/api/internal/triage-runs/{run_id}/remediations",
                    json={"projectId": self.project_id, "remediations": rows},
                    headers=INTERNAL_HEADERS,
                )
                response.raise_for_status()
                result = response.json()
        except Exception:
            logger.exception("Failed to save the fix list")
            await self.callback.on_error(
                safe_error("save_failed"), recoverable=True, code="save_failed")
            return {}

        logger.info(f"Fix list: {result}")
        return {
            "remediations_created": int(result.get("created") or 0),
            "remediations_updated": int(result.get("updated") or 0),
            "remediations_deleted": int(result.get("deleted") or 0),
            "remediations_skipped": int(result.get("skipped") or 0),
        }

    def _parse_findings(self, content) -> RemediationDraft:
        """Parse LLM output to extract remediation findings."""
        text = ""
        if isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "text":
                    text += block["text"]
                elif isinstance(block, str):
                    text += block
        else:
            text = str(content)

        # Extract JSON from code fence
        json_match = re.search(r'```json\s*([\s\S]*?)```', text)
        if not json_match:
            json_match = re.search(r'(\[[\s\S]*\])', text)

        if not json_match:
            logger.warning("No JSON found in LLM response")
            return RemediationDraft(summary="Analysis complete but no structured output found.")

        try:
            raw_json = json_match.group(1).strip()
            try:
                data = json.loads(raw_json)
            except json.JSONDecodeError as first_err:
                logger.warning(f"Initial JSON parse failed: {first_err}")
                logger.debug(f"Raw JSON (first 500): {raw_json[:500]}")
                logger.debug(f"Raw JSON (last 500): {raw_json[-500:]}")
                # Fallback: extract individual JSON objects via regex
                obj_pattern = re.compile(r'\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}', re.DOTALL)
                objects = obj_pattern.findall(raw_json)
                data = []
                for obj_str in objects:
                    try:
                        obj = json.loads(obj_str)
                        # Must have at least a title to be a valid finding
                        if isinstance(obj, dict) and "title" in obj:
                            data.append(obj)
                    except json.JSONDecodeError:
                        continue
                if data:
                    logger.warning(f"Recovered {len(data)} findings from malformed JSON")
                else:
                    raise first_err
            if not isinstance(data, list):
                data = [data]

            findings = []
            by_severity = {}
            by_type = {}

            for item in data:
                finding = TriageFinding(
                    title=item.get("title", "Unnamed Finding"),
                    description=item.get("description", ""),
                    severity=item.get("severity", "medium"),
                    priority=item.get("priority", 0),
                    category=item.get("category", "vulnerability"),
                    remediation_type=item.get("remediation_type", "code_fix"),
                    affected_assets=item.get("affected_assets", []),
                    cvss_score=item.get("cvss_score"),
                    cve_ids=item.get("cve_ids", []),
                    cwe_ids=item.get("cwe_ids", []),
                    capec_ids=item.get("capec_ids", []),
                    evidence=item.get("evidence", ""),
                    attack_chain_path=item.get("attack_chain_path", ""),
                    exploit_available=item.get("exploit_available", False),
                    cisa_kev=item.get("cisa_kev", False),
                    solution=item.get("solution", ""),
                    fix_complexity=item.get("fix_complexity", "medium"),
                    estimated_files=item.get("estimated_files", 0),
                    target_repo=item.get("target_repo", ""),
                    target_branch=item.get("target_branch", "main"),
                )
                findings.append(finding)

                sev = finding.severity
                by_severity[sev] = by_severity.get(sev, 0) + 1
                rtype = finding.remediation_type
                by_type[rtype] = by_type.get(rtype, 0) + 1

            return RemediationDraft(
                findings=findings,
                summary=f"Found {len(findings)} remediations across {len(by_severity)} severity levels.",
                by_severity=by_severity,
                by_type=by_type,
            )
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse LLM JSON: {e}")
            return RemediationDraft(summary=f"JSON parse error: {e}")

    async def _init_llm(self, settings: dict):
        """Initialize LLM client using centralized setup_llm."""
        from orchestrator_helpers.llm_setup import setup_llm, _resolve_provider_key

        model = settings.get("llm_model", "")
        logger.info(f"Setting up triage LLM: {model}")

        user_providers = settings.get("user_llm_providers", [])
        custom_config = settings.get("custom_llm_config")

        openai_p = _resolve_provider_key(user_providers, "openai")
        anthropic_p = _resolve_provider_key(user_providers, "anthropic")
        openrouter_p = _resolve_provider_key(user_providers, "openrouter")
        bedrock_p = _resolve_provider_key(user_providers, "bedrock")
        deepseek_p = _resolve_provider_key(user_providers, "deepseek")
        gemini_p = _resolve_provider_key(user_providers, "gemini")
        glm_p = _resolve_provider_key(user_providers, "glm")
        kimi_p = _resolve_provider_key(user_providers, "kimi")
        qwen_p = _resolve_provider_key(user_providers, "qwen")
        xai_p = _resolve_provider_key(user_providers, "xai")
        mistral_p = _resolve_provider_key(user_providers, "mistral")

        return setup_llm(
            model,
            openai_api_key=(openai_p or {}).get("apiKey"),
            anthropic_api_key=(anthropic_p or {}).get("apiKey"),
            openrouter_api_key=(openrouter_p or {}).get("apiKey"),
            deepseek_api_key=(deepseek_p or {}).get("apiKey"),
            gemini_api_key=(gemini_p or {}).get("apiKey"),
            glm_api_key=(glm_p or {}).get("apiKey"),
            kimi_api_key=(kimi_p or {}).get("apiKey"),
            qwen_api_key=(qwen_p or {}).get("apiKey"),
            xai_api_key=(xai_p or {}).get("apiKey"),
            mistral_api_key=(mistral_p or {}).get("apiKey"),
            aws_access_key_id=(bedrock_p or {}).get("awsAccessKeyId"),
            aws_secret_access_key=(bedrock_p or {}).get("awsSecretKey"),
            aws_bearer_token=(bedrock_p or {}).get("awsBearerToken"),
            aws_region=(bedrock_p or {}).get("awsRegion") or "us-east-1",
            custom_llm_config=custom_config,
        )

    async def _call_llm(self, system: str, messages: list, tools: list = None) -> dict:
        """Call the LLM and return structured response."""
        from langchain_core.messages import SystemMessage, HumanMessage, AIMessage, ToolMessage

        lc_messages = [SystemMessage(content=system)]

        for msg in messages:
            role = msg["role"]
            content = msg["content"]
            if role == "user":
                if isinstance(content, list):
                    # Check if all items are tool_results — use ToolMessage for each
                    all_tool_results = all(
                        isinstance(item, dict) and item.get("type") == "tool_result"
                        for item in content
                    )
                    if all_tool_results:
                        for item in content:
                            tool_content = item.get("content", "")
                            if item.get("is_error"):
                                tool_content = f"[ERROR] {tool_content}"
                            lc_messages.append(ToolMessage(
                                content=tool_content,
                                tool_call_id=item.get("tool_use_id", ""),
                            ))
                    else:
                        parts = []
                        for item in content:
                            if isinstance(item, dict) and item.get("type") == "tool_result":
                                prefix = "[ERROR] " if item.get("is_error") else ""
                                parts.append(
                                    f"Tool result ({item.get('tool_use_id', '')}):\n"
                                    f"{prefix}{item.get('content', '')}"
                                )
                            else:
                                parts.append(str(item))
                        lc_messages.append(HumanMessage(content="\n\n".join(parts)))
                else:
                    lc_messages.append(HumanMessage(content=content))
            elif role == "assistant":
                # Extract text content
                if isinstance(content, list):
                    text_parts = [
                        b["text"] for b in content
                        if isinstance(b, dict) and b.get("type") == "text"
                    ]
                    ai_content = "\n".join(text_parts) if text_parts else ""
                else:
                    ai_content = content or ""

                # Reconstruct tool_calls for LangChain if the assistant used tools
                tool_uses = msg.get("tool_uses", [])
                if tool_uses:
                    lc_tool_calls = [
                        {
                            "id": tu["id"],
                            "name": tu["name"],
                            "args": tu["input"],
                        }
                        for tu in tool_uses
                    ]
                    lc_messages.append(AIMessage(
                        content=ai_content,
                        tool_calls=lc_tool_calls,
                    ))
                else:
                    lc_messages.append(AIMessage(content=ai_content))

        # Bind tools if provided
        llm = self.llm_client
        if tools:
            llm = llm.bind_tools([
                {
                    "name": t["name"],
                    "description": t["description"],
                    "parameters": t["input_schema"],
                }
                for t in tools
            ])

        response = await llm.ainvoke(lc_messages)

        result = {
            "content": (
                response.content
                if isinstance(response.content, list)
                else [{"type": "text", "text": response.content}]
            ),
            "stop_reason": "end_turn",
            "tool_uses": [],
        }

        if hasattr(response, "tool_calls") and response.tool_calls:
            result["stop_reason"] = "tool_use"
            for tc in response.tool_calls:
                result["tool_uses"].append({
                    "id": tc.get("id", ""),
                    "name": tc["name"],
                    "input": tc["args"],
                })

        return result

    async def cleanup(self):
        """Clean up resources."""
        await self.neo4j.close()
