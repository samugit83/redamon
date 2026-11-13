---
name: priority-board-triage
description: >
  The Priority Board's three-layer score model (rules BASE, REVIEW by the built-in
  AI or an MCP agent, a person's DECISION) and who may write which layer. A writer
  that sets a final score itself, or touches another layer, silently undoes a
  review or a person's verdict at the next run.
  Trigger: editing agentic/cypherfix_triage/ (score_model, layers, evidence,
  orchestrator, finding_ops, prompts/review.py); editing triage_mixin.py; editing
  webapp/src/lib/triage/, the /api/triage routes, the Triage board components, or
  the MCP triage tools (triageTools.ts, verdictTools.ts).
license: MIT
metadata:
  author: redamon
  version: "1.1.0"
  scope: [root, agentic, webapp]
  auto_invoke:
    - "Changing how a triage score, review or verdict is computed or written"
    - "Editing the Priority Board, the triage graph mixin, or the MCP triage tools"
---

## When to Use

- Changing the risk model, the evidence bundle, the review prompt or its validation.
- Adding a writer of any `triage_*` property: a run step, a route, an MCP tool, a migration.
- Adding a reader of the board state: a report, an MCP tool, a filter, a UI chip.

For the Cypher itself, also follow `graph-db-writes`; for a new MCP tool,
`mcp-server-tools`.

---

## Critical Rules

- **NOBODY writes a final score.** `triage_priority_score`, `triage_tier`,
  `triage_tier_rule`, `triage_risk`, `triage_factors`, `triage_state`,
  `triage_decided_by`, `triage_disposition` and `triage_blocker` (the mixin's
  `_FINAL_SET`) come ONLY from `score_model.combine_layers()`, reached through
  `layers.combine_props()`. A writer changes ITS layer and asks `combine` for the
  final inside the same transaction. Setting a final directly is how a review or
  a verdict used to vanish at the next run.
- **Each writer touches one layer.**

  | Writer | Layer | Method |
  | --- | --- | --- |
  | a run's publish | BASE (+ a builtin REVIEW it made) | `publish_triage_layers` |
  | an MCP agent's review | REVIEW, channel `mcp` | `write_review` |
  | a person (app, or MCP with channel `mcp`) | DECISION | `set_human_verdict` |

  A publish never writes a decision, `:Muted` or `updated_at`; a review never
  writes a decision or the base; a verdict never writes the base or a review.
- **NEVER write `updated_at` from triage.** It is the scan's "last seen" stamp:
  the prune reads it, and the publish's guard skips a node whose `updated_at`
  moved since the run read it. A triage write that bumped it would make every
  finding look re-ingested.
- **Every single-finding write is lock-then-read, in one managed transaction.**
  `SET n._triage_lock = true REMOVE n._triage_lock` first, then read the node,
  the live proof (`_LIVE_PROOF`) and the current layers, then decide and write.
  Match exactly one node, else `ambiguous`. A timeout raises `TriageWriteBusy`,
  which the API returns as 503 `busy`. Never read proof from a run's snapshot.
- **Live proof is proof of THIS finding.** `_LIVE_PROOF` mirrors
  `score_model.is_proven`; it must not read `triage_proof`, which records proof
  on the finding's HOST. Reading it lifted every finding on a compromised host
  to T1 "proven" at its next rescore. (The mute guards' `_PROVEN` does read it,
  on purpose: refusing a mute on a compromised host is the safe direction.)
- **An `app` decision is never changed or reset over MCP** (`decided_in_app`).
  Only the owner's own `app`-channel decisions teach a detector's prior
  (`coalesce(triage_verdict_by, user_id)` is the owner, in
  `agentic/cypherfix_triage/fact_queries.py`): a
  collaborator's verdict never does.
- **The tenant is the project's owner; the person goes in a field of its own.**
  Every triage call and write carries the owner as `user_id` (`triageCaller(auth)`
  in [routeCaller.ts](../../webapp/src/lib/triage/routeCaller.ts),
  `assertMcpProjectAccess(...).userId` over MCP). Who acted is `triagePerson(auth)`:
  `verdictBy` (stored as `triage_verdict_by`, sent only when not the owner),
  `muted_by`, the audit actor, and a run's `actor_user_id`. A collaborator's id
  as `user_id` reads and writes an empty graph of their own.
- **A review is valid only while `triage_ai_evidence_hash == triage_evidence_hash`.**
  The hash is `bundle_hash(build_bundle(...))`: normalised, secret-redacted,
  capped. Changing the bundle, the redaction or the cap changes every hash and
  expires every review: bump `REVIEW_PROMPT_VERSION` deliberately, never by
  accident.
- **A run never reviews over a valid `mcp` review**, and re-reviews its own
  (`builtin`) only on a model or prompt-version change. Fix-item text
  (`fix_lever`, `ai_quote`) comes from builtin reviews only.
- **Keep the legacy readers tolerant.** Unknown or legacy values mean "no
  layer", never a decision. `triage_source = 'ai'` is a builtin false-positive
  review; a missing `triage_verdict_channel` means `app`. The first publish after
  an upgrade adopts an unchanged review-v1 review through `build_bundle_legacy`,
  and unmute applies the same cleanup to muted nodes. Readers that branch on this:
  `score_model.finding_state`, `reportData.ts`, `projectRisk.ts`,
  `webapp/src/lib/triage/reportable.ts`, `webapp/src/lib/triage/disposition.ts`,
  `tooling/scripts/triage_eval.py`.
- **An AI review never removes a finding from a deliverable.** The report,
  Insights and the MCP analytics count through `reportable.ts`: only a person's
  `likely_noise` (with `triage_source = 'human'`) or a resolved state takes a
  finding out of their numbers. A reviewer reads target-controlled text, so its
  `false_positive` stays counted and is labelled. The same holds for a finding's
  disposition (`disposition.ts`, built on `reportable.ts`): an AI false positive
  is a `candidate` with a blocker, never `excluded` and never `reportable`.
- **The stored disposition and the read-side one are one rule in two languages.**
  `score_model.disposition_of` stores it; `disposition.ts` shows the stored
  answer when it is whole and computes it otherwise. Change a rule, a gate or a
  blocker's words in both, with the vector files they share
  (`disposition.vectors.json`, `disposition.gates.vectors.json`): the parity
  test, `agentic/tests/test_disposition_parity.py`, fails on a drift. A reader
  decides "excluded" live (`reportable.ts`) before it trusts a stored answer.
- **A new stored `triage_*` property goes in `TRIAGE_PROPS`** (triage_mixin.py),
  which feeds `triage_graph_migrate.py`, and in `TRIAGE_PROPERTIES`
  (`webapp/src/lib/triage/properties.ts`), which keeps it out of the Recon Delta.
  Agent-writable text also goes in `TRIAGE_TEXT_PROPERTIES`, so
  `buildNodeContext` never hands it to the in-app agent. Declare it in
  `graph_db/schema_sections.md` and re-seed the catalog.

---

## Pattern: a writer asks combine for the final

```python
# graph_db/mixins/recon/triage_mixin.py - write_review, trimmed
def work(tx):
    found = self._lock_findings(tx, user_id, project_id, node_id, label)  # lock, THEN read
    ...                                                  # not_found / ambiguous
    props = dict(rec["props"])
    outcome = decide(props, rec["proven_now"], rec["updated_at"], rec["label"])
    if outcome.get("refused"):
        return {"written": False, "reason": outcome["refused"]}   # nothing written
    review = self._clean_review(outcome["review"])       # only THIS layer's keys
    tx.run("MATCH (n) WHERE elementId(n) = $eid SET n += $review", ...)
    props.update(review)
    final = self._clean_final(combine(props, rec["proven_now"]))  # layers.combine_props
    tx.run(f"MATCH (n) WHERE elementId(n) = $eid SET {self._FINAL_SET}", ...)
return self._write_tx(self.driver, work, timeout)       # TriageWriteBusy on timeout
```

---

## Commands

```bash
./agentic/run_tests.sh tests/test_score_model.py          # combine_layers + the model
./agentic/run_tests.sh tests/test_triage_orchestrator_flow.py
./agentic/run_tests.sh tests/test_triage_finding_ops.py
# root tests run in the agent image; the *_live suites need Neo4j and self-skip without it
./redamon.sh test unit
cd webapp && npx vitest run src/lib/triage src/lib/mcp src/app/api/triage
```

---

## Resources

- [Priority-Board.md](../../redamon.wiki/Priority-Board.md) - the user-facing model: layers, Decided by, Reset, the detail panel, MCP
- [README.CYPHERFIX_AGENTS.md](../../docs/readmes/README.CYPHERFIX_AGENTS.md) - run steps, publish, run protocol
- [graph_db/schema_sections.md](../../graph_db/schema_sections.md) - every `triage_*` property, by layer
- Related skills: `graph-db-writes`, `mcp-server-tools`, `rbac-authz`, `redamon-testing`
