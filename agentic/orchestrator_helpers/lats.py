"""LATS (Language Agent Tree Search) — bounded, value-guided search over
executed exploit probes.

This module is the self-contained LATS engine. See internal/LATS_integration.md
for the full design. The orchestrator's only contact with LATS is:
  1. state.py declaring the LATS state fields (LangGraph strips undeclared keys).
  2. a single `lats_hook(...)` call inside think_node (added in Step 2).

Everything here is stateless: all per-session search state lives in the
`_exploit_tree` dict on AgentState, so concurrent sessions never share LATS
state. The tree rides inside AgentState and the Postgres checkpointer persists
it for free.

STEP 1 (this file's first cut) ships the PURE engine only:
  value function, UCT, select, backprop, expand (structured probe generation),
  tree bookkeeping, activation gate, and the completion/archive helpers.
The think_node hook, streaming emission, and decision override arrive in later
steps and build on these primitives.
"""

from __future__ import annotations

import json
import logging
import math
import re
from typing import Any, List, Optional

from project_settings import get_setting, TOOL_MUTEX_GROUPS, is_dangerous_call
from orchestrator_helpers.error_class import is_diagnostic_failure
from state import ExploitTree, ExploitTreeNode

logger = logging.getLogger(__name__)


# =============================================================================
# Small accessors — value helpers must tolerate both a pydantic
# OutputAnalysisInline and a plain dict (tests feed dicts).
# =============================================================================

def _attr(obj: Any, key: str, default: Any = None) -> Any:
    if obj is None:
        return default
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


# =============================================================================
# VALUE FUNCTION (§6) — inverts compute_productivity_score's "badness" into
# "goodness" (higher = closer to a foothold), enriched with error_class.
# All inputs are already computed upstream; lats_value adds no I/O.
# =============================================================================

def _exploit_succeeded(step: dict, analysis: Any, credited: bool = True) -> bool:
    """True when the just-executed probe reached a foothold.

    Attribution order (§6, §20.2): the step's own flag, then a per_step entry
    keyed by step_index (authoritative localization for a wave), then the
    aggregate analysis flag — but the aggregate is only credited to the ONE
    designated child (`credited=True`). Without this, a wave-level
    exploit_succeeded=True would mark EVERY sibling terminal (Bug: over-credit)."""
    if step and step.get("exploit_succeeded"):
        return True
    if step is not None:
        idx = step.get("_step_index")
        for ps in (_attr(analysis, "per_step", []) or []):
            if _attr(ps, "step_index", -1) == idx and _attr(ps, "exploit_succeeded", False):
                return True
    if credited:
        return bool(_attr(analysis, "exploit_succeeded", False))
    return False


def _verdict_for(step: dict, analysis: Any) -> str:
    """The ProductivityVerdict.verdict for this step. A per_step entry (keyed
    by step_index) wins; otherwise the aggregate productivity verdict."""
    if step is not None:
        idx = step.get("_step_index")
        per_step = _attr(analysis, "per_step", []) or []
        if idx is not None:
            for ps in per_step:
                if _attr(ps, "step_index", -1) == idx:
                    v = _attr(ps, "verdict", "")
                    if v:
                        return v
        # A single-step turn may stamp the verdict directly on the step.
        if step.get("verdict"):
            return step["verdict"]
    prod = _attr(analysis, "productivity", None)
    return _attr(prod, "verdict", "") or ""


def _new_finding_confidence(step: dict, analysis: Any, credited: bool = True) -> int:
    """Confidence (0-100) of any ChainFinding attributed to this step.

    A per_step entry keyed by step_index wins (authoritative per-child); the
    aggregate finding is credited only to the ONE designated child
    (`credited=True`), else 0 — otherwise every wave sibling inherits the
    aggregate confidence and its value is inflated (Bug: over-credit)."""
    if step is not None:
        idx = step.get("_step_index")
        per_step = _attr(analysis, "per_step", []) or []
        if idx is not None:
            for ps in per_step:
                if _attr(ps, "step_index", -1) == idx and _attr(ps, "finding", ""):
                    return int(_attr(ps, "confidence", 0) or 0)
    if not credited:
        return 0
    findings = _attr(analysis, "chain_findings", []) or []
    best = 0
    for f in findings:
        c = int(_attr(f, "confidence", 0) or 0)
        if c > best:
            best = c
    return best


# =============================================================================
# W4 — RESPONSE-CLASS ENGINE (LLM-classified). The error_class bucket
# (status/timing only) and the 6-value verdict enum collapse many distinct
# outcomes — a bypassable input filter, a WAF wall, an auth wall, a leaked SQL
# error, a genuinely dead endpoint — into one flat `application_4xx`/`blocked`
# penalty, so bypassable vectors get pruned as if dead. `response_class` is a
# richer, app-semantic label the THINK-LLM emits per step (PerStepAnalysis.
# response_class) from the 24-class taxonomy below; each class carries a target
# value (detection-confidence x proximity-to-foothold, grounded in oracle
# strength: in-band/OOB > error > differential > timing > passive) and an
# actionable reflection. There is NO deterministic body classifier — the LLM,
# which already reads every response to produce output_analysis, is the sole
# classifier. Transport/tool/parse-time failures stay on error_class (a
# mechanical status/timing fact, not app semantics) and score neutral 0.15.
# Every probe is classified; the legacy verdict/error_class formula survives only
# as the per-probe fallback when the LLM abstains (no valid class on that probe).
# =============================================================================

# Class -> target local_value (0..1). Higher = closer to a foothold / more worth
# pursuing. Above LATS_PRUNE_FLOOR (0.15) => the branch survives; below => pruned.
# By construction every "keep working this vector" class sits above the floor and
# every "abandon" class below it, so no prune-exemption special-case is needed.
_RC_SCORES = {
    # Tier A — confirmed foothold (weaponize)
    "exploit_confirmed":      0.95,
    # Tier B — strong lead, near-confirmed (build oracle / escalate)
    "oob_callback":           0.85,
    "error_leak":             0.72,
    "outbound_fetch":         0.68,
    "boolean_differential":   0.66,
    "info_disclosure":        0.64,
    "time_differential":      0.60,
    # Tier C — weak progress / attack surface (refine payload)
    "reflected_unsanitized":  0.50,
    "partial_filter_bypass":  0.48,
    # Tier F — server fault / opportunity (lean in)
    "server_error_5xx":       0.42,
    # Tier D — bypassable block (mutate / evade, keep alive)
    "encoding_normalization": 0.35,
    "filter_blacklist":       0.34,
    "waf_block":              0.26,
    # Tier E — precondition / change-and-retry
    "privilege_required":     0.30,
    "wrong_method":           0.27,
    "wrong_content_type":     0.25,
    "auth_required":          0.22,
    "rate_limited":           0.20,
    "size_limit":             0.18,
    # Tier G — hard block / vector closed (pivot away)
    "filter_whitelist":       0.10,
    "geo_legal_block":        0.05,
    # Tier I — dead / no signal (abandon)
    "benign_no_signal":       0.06,
    "dead_endpoint":          0.03,
    "duplicate":              0.00,
}
RESPONSE_CLASSES = frozenset(_RC_SCORES)   # the 24 valid labels

# Actionable one-line lesson per class — the MOVE it implies. Fed to the next
# expand's context and the cross-tree digest, and (for the sequential agent) the
# next-move prompt hint. Set whenever a class is recognized, not only on prune.
_RC_REFLECTIONS = {
    "exploit_confirmed":      "vuln CONFIRMED here; weaponize and escalate this vector",
    "oob_callback":           "out-of-band callback fired; blind vuln confirmed, build an OOB exfil channel",
    "error_leak":             "interpreter/error leaked; fingerprint the engine and weaponize from the error",
    "outbound_fetch":         "server fetched our URL (SSRF); pivot to internal targets / cloud metadata",
    "boolean_differential":   "stable true/false differential; build a boolean extraction oracle",
    "info_disclosure":        "internal info leaked; pivot using the disclosed path/version/host",
    "time_differential":      "timing tracked the injected delay; corroborate over N, then time-based extraction",
    "reflected_unsanitized":  "input reflected RAW; escalate to execution in this context (not yet proven)",
    "partial_filter_bypass":  "some characters survived the filter; context-escape with the surviving charset",
    "server_error_5xx":       "our input broke the backend (5xx); refine the injection, harvest any leaked trace",
    "encoding_normalization": "payload was normalized, not rejected; try an encoding-differential (double-encode)",
    "filter_blacklist":       "specific token blocked (blacklist); SAME vector viable with encoding / mutation",
    "waf_block":              "WAF blocked the request; try vendor-specific evasion once, else pivot the vector",
    "privilege_required":     "authenticated but forbidden (authz); try IDOR / privesc / 403-bypass tricks",
    "wrong_method":           "endpoint exists, wrong method; retry with an allowed verb",
    "wrong_content_type":     "endpoint wants a different Content-Type; resend it (enables XXE / type-confusion)",
    "auth_required":          "needs credentials; obtain/replay a session before retrying this vector",
    "rate_limited":           "throttled; back off / rotate identity, do NOT abandon the vector",
    "size_limit":             "payload too large; shorten / relocate it, or oversize past WAF inspection",
    "filter_whitelist":       "strict whitelist; only parser-confusion tricks may pass, else abandon this param",
    "geo_legal_block":        "geo/legal block; change egress or abandon",
    "benign_no_signal":       "endpoint live but no signal; try a different attack or move on",
    "dead_endpoint":          "endpoint absent (404 / soft-404); abandon and pivot",
    "duplicate":              "identical to a prior probe; do not repeat",
}

# Reflection-conditioned expansion: when LATS grows children FROM a node, the
# node's response_class dictates what the next wave must contain. This turns a
# kept-alive lead (W4) into the specific follow-up that converts it, instead of a
# generic "pivot if blocked" fan-out. Keyed by the survivable classes (those at or
# above the prune floor, i.e. the ones that actually get expanded); a class absent
# here (a pruned/dead class, or an unclassified node) falls back to the generic ask.
_RC_EXPAND_DIRECTIVES = {
    "exploit_confirmed":      "This probe CONFIRMED the vuln. Propose probes that WEAPONIZE and escalate it (extract data / gain a shell / reach the flag), not new vectors.",
    "oob_callback":           "A blind out-of-band callback fired. Propose probes that exfiltrate data through the OOB channel and confirm impact.",
    "error_leak":             "The response leaked an interpreter/DB error. Propose EXTRACTION payloads that weaponize the leaked engine (e.g. UNION / extractvalue for SQL, class-traversal for a template) on the SAME parameter.",
    "outbound_fetch":         "The server fetched our URL (SSRF). Propose probes that pivot to internal targets / cloud metadata / internal port scans through this sink.",
    "boolean_differential":   "The true/false responses differ (a boolean oracle). Propose the boolean-extraction sequence that reads data one character at a time on the SAME parameter.",
    "info_disclosure":        "The response leaked internal detail (path / version / host / source). Propose probes that USE the disclosed detail to reach the next stage.",
    "time_differential":      "The response delay tracked an injected sleep. Propose probes that corroborate the timing, then extract data via time-based inference on the SAME parameter.",
    "reflected_unsanitized":  "Our input was reflected RAW. Propose probes that ESCALATE the reflection to execution in this exact context (attribute / JS-string / HTML) on the SAME parameter.",
    "partial_filter_bypass":  "Some characters survived the filter. Propose probes that context-escape using ONLY the surviving character set on the SAME parameter.",
    "server_error_5xx":       "Our input caused a backend 5xx (it reached real logic). Propose probes that refine the SAME injection to turn the crash into controlled output; harvest any leaked trace.",
    "encoding_normalization": "The payload was normalized/decoded, not rejected. Propose ENCODING-DIFFERENTIAL probes (double-encode, overlong UTF-8, mixed case) that survive the validator but decode at the sink, on the SAME parameter.",
    "filter_blacklist":       "A specific token was blocked (a bypassable blacklist). Propose ENCODED / MUTATED variants of the SAME payload on the SAME parameter (case, comments, nesting, alternate syntax, encoding). Do NOT pivot to a different vector.",
    "waf_block":              "A WAF blocked the request. Propose EVASION variants of the SAME payload (encoding, casing, chunking, parameter pollution); pivot only if evasion clearly fails.",
    "privilege_required":     "Authenticated but forbidden (authz). Propose ACCESS-CONTROL bypass probes: IDOR (change the object id), forced browse, verb/header tricks (X-Original-URL, X-Forwarded-For), role/JWT tampering.",
    "wrong_method":           "The endpoint exists but rejects this HTTP method. Propose the SAME probe with the allowed method(s) (see the Allow header) or verb tampering.",
    "wrong_content_type":     "The endpoint wants a different Content-Type. Propose the SAME probe re-sent with the right Content-Type (json / xml / multipart); this may enable XXE or type-confusion.",
    "auth_required":          "The vector needs credentials first. Propose probes that acquire/replay a session (default creds, token, auth bypass), then retry this vector.",
    "rate_limited":           "We are being throttled (not the payload's fault). Propose the SAME line at a slower pace / rotated identity; do NOT abandon the vector.",
    "size_limit":             "The payload was too large. Propose SHORTER / chunked variants of the SAME payload, or relocate it to an unlimited field.",
}


def _response_class_for(step: dict, analysis: Any) -> str:
    """The THINK-LLM's response_class for this step, localized via
    PerStepAnalysis.response_class (keyed by _step_index) or stamped on the step.
    LLM-only — there is no code classifier. Returns "" when the label is absent or
    not one of the 24 valid classes (e.g. "inconclusive"), so scoring falls back to
    the legacy value and an unclassified response never changes behavior."""
    if step is None:
        return ""
    idx = step.get("_step_index")
    for ps in (_attr(analysis, "per_step", []) or []):
        if _attr(ps, "step_index", -1) == idx:
            rc = _attr(ps, "response_class", "") or ""
            if rc in RESPONSE_CLASSES:
                return rc
    rc = (step.get("response_class") or "")
    return rc if rc in RESPONSE_CLASSES else ""


def _legacy_deadend_delta(verdict: str, ec: str) -> float:
    """The pre-W4 dead-end penalties. Used only as the graceful fallback when the
    LLM abstained on this probe (no recognized response_class), so legacy behavior is
    exactly preserved."""
    d = 0.0
    if verdict in ("blocked", "duplicate", "no_progress"):
        d -= 0.3
    if ec == "application_4xx":               # 403 / WAF / semantic rejection
        d -= 0.2
    return d


def _legacy_web_value(step: dict, analysis: Any, credited: bool = True) -> float:
    """The pre-W4 web value formula (no response-class). This is the toggle-OFF
    path AND the ranking used for aggregate credit attribution (`_credited_child`),
    so W4's keep-alive boosts can NEVER change which child is credited a foothold
    or perturb legacy scoring — the parity guarantee lives here."""
    ec = step.get("error_class", "") if step else ""
    verdict = _verdict_for(step, analysis)
    # (0) Diagnostic failure: the probe never reached the app (bad quoting, DNS,
    #     tool crash, parse-time 5xx). NEUTRAL, so UCT retries rather than
    #     abandoning a possibly-live vector. Small floor: not pruned, not deep.
    if is_diagnostic_failure(ec):
        return 0.15
    v = 0.0
    v += 0.5 * (_new_finding_confidence(step, analysis, credited) / 100.0)  # (a) evidence
    if verdict in ("new_info", "diagnostic_progress"):                       # (b) informative
        v += 0.3
    if ec == "application_5xx_normal":       # DB / business-logic path reached
        v += 0.2
    if verdict == "confirmation":
        v += 0.1
    v += _legacy_deadend_delta(verdict, ec)                                  # (c) dead-ends
    return max(0.0, v)


def _lats_value_web(step: dict, analysis: Any, credited: bool = True) -> float:
    """Web-exploitation value. The THINK-LLM classifies every probe, so its
    recognized response_class IS the value (the class already encodes detection-
    confidence x proximity-to-foothold). A transport / parse-time failure is a
    mechanical fact, so error_class short-circuits to the neutral 0.15 floor BEFORE
    the class is consulted (a class can never rescue a probe that never reached the
    app). The legacy verdict/error_class formula is used ONLY as the per-probe
    fallback when the LLM abstained (no valid class on this probe)."""
    ec = step.get("error_class", "") if step else ""
    if is_diagnostic_failure(ec):
        return 0.15                            # Tier H (infra) — owned by error_class

    rc = _response_class_for(step, analysis)
    if rc in _RC_SCORES:
        return _RC_SCORES[rc]
    return _legacy_web_value(step, analysis, credited)   # LLM abstained -> legacy fallback


def _privilege_increased(before: dict, after: dict) -> bool:
    return _delta_count(before, after, "privilege_escalation") > 0


def _new_session(before: dict, after: dict) -> bool:
    return _len_of(after, "sessions") > _len_of(before, "sessions")


def _new_credentials(before: dict, after: dict) -> bool:
    return _len_of(after, "credentials") > _len_of(before, "credentials")


def _new_host_reached(before: dict, after: dict) -> bool:
    return _len_of(after, "hosts") > _len_of(before, "hosts")


def _len_of(snapshot: Optional[dict], key: str) -> int:
    if not snapshot:
        return 0
    val = snapshot.get(key)
    try:
        return len(val) if val is not None else 0
    except TypeError:
        return 0


def _delta_count(before: Optional[dict], after: Optional[dict], finding_type: str) -> int:
    def _count(snap):
        if not snap:
            return 0
        return int(snap.get(f"finding_{finding_type}", 0) or 0)
    return _count(after) - _count(before)


def _lats_value_post_expl(step: dict, analysis: Any, before: dict, after: dict,
                          credited: bool = True) -> float:
    """Post-exploitation value from engagement-state deltas (§6.1). In this
    phase error_class 4xx/5xx branches are inert, so score from privilege /
    session / credential / host / finding growth instead."""
    if is_diagnostic_failure(step.get("error_class", "") if step else ""):
        return 0.15                                  # command never ran; retry
    v = 0.0
    if _privilege_increased(before, after):
        v += 0.6
    if _new_session(before, after):
        v += 0.5
    if _new_credentials(before, after):
        v += 0.4
    if _new_host_reached(before, after):
        v += 0.4
    if _new_finding_confidence(step, analysis, credited) > 0:
        v += 0.3
    if _verdict_for(step, analysis) in ("no_progress", "duplicate"):
        v -= 0.3
    return max(0.0, min(1.0, v))


def lats_value(step: dict, analysis: Any, phase: Optional[str] = None,
               before: Optional[dict] = None, after: Optional[dict] = None,
               credited: bool = True) -> float:
    """Value of a just-executed probe. Terminal success is the strong reward;
    otherwise dispatch on phase (§6.1). `credited` gates whether the aggregate
    wave-level exploit/finding signal is attributed to THIS child (§20.2)."""
    if _exploit_succeeded(step, analysis, credited):
        return 1.0
    if phase == "post_exploitation":
        return _lats_value_post_expl(step, analysis, before or {}, after or {}, credited)
    return _lats_value_web(step, analysis, credited)


# =============================================================================
# UCT / SELECT / BACKPROP (§6) — textbook and pure.
# =============================================================================

def uct(node: ExploitTreeNode, parent_visits: int, c: float) -> float:
    if node.visits == 0:
        return float("inf")   # always try an unvisited frontier node once
    return node.value + c * math.sqrt(math.log(max(parent_visits, 1)) / node.visits)


def _live_children(tree: ExploitTree, node: ExploitTreeNode) -> List[ExploitTreeNode]:
    return [tree.nodes[cid] for cid in node.children
            if tree.nodes[cid].status in ("proposed", "evaluated", "executing")]


def _has_proposed_children(tree: ExploitTree, node: ExploitTreeNode) -> bool:
    return any(tree.nodes[cid].status == "proposed" for cid in node.children)


def lats_select(tree: ExploitTree, c: float) -> str:
    """Descend from root by UCT to a node the hook can act on this turn: one
    that either has unexecuted (proposed) children to fire, or can be expanded,
    or is a dead frontier. Stops at the first such node.

    NOTE: this refines the doc's textbook pseudocode (§6) to stay consistent
    with the hook flow (§5.3), which needs SELECT to return the PARENT of the
    next wave (a node with proposed children), not descend past it.
    """
    cur = tree.nodes[tree.root_id]
    while True:
        # A node with pending probes is where the next wave fires.
        if _has_proposed_children(tree, cur):
            return cur.id
        # An evaluated leaf with room to grow is expanded next.
        if _can_expand(cur):
            return cur.id
        # Otherwise descend into the best evaluated child by UCT.
        eval_children = [tree.nodes[cid] for cid in cur.children
                         if tree.nodes[cid].status == "evaluated"]
        if not eval_children:
            return cur.id   # dead frontier: nothing to do under this node
        cur = max(eval_children, key=lambda n: uct(n, cur.visits, c))


def lats_backprop(tree: ExploitTree, node_id: str, value: float) -> None:
    """Push value up the ancestor chain (running max), incrementing visits."""
    nid: Optional[str] = node_id
    while nid is not None:
        n = tree.nodes[nid]
        n.visits += 1
        n.value = max(n.value, value)   # running max keeps a branch hot if any descendant is promising
        nid = n.parent_id


# =============================================================================
# EXPANDABILITY / FRONTIER / BUDGET (§8)
# =============================================================================

def _can_expand(node: ExploitTreeNode) -> bool:
    return (node.status == "evaluated"
            and node.depth < get_setting("LATS_MAX_DEPTH", 6)
            and not node.children)


def _executing_children(tree: ExploitTree) -> List[ExploitTreeNode]:
    return [n for n in tree.nodes.values() if n.status == "executing"]


def _proposed_children(tree: ExploitTree, node: ExploitTreeNode) -> List[ExploitTreeNode]:
    return [tree.nodes[cid] for cid in node.children
            if tree.nodes[cid].status == "proposed"]


def _open_leaves(tree: ExploitTree) -> List[ExploitTreeNode]:
    """Live (proposed/evaluated) nodes with no live children — the frontier."""
    leaves = []
    for n in tree.nodes.values():
        if n.status not in ("proposed", "evaluated"):
            continue
        if not _live_children(tree, n):
            leaves.append(n)
    return leaves


def _single_open_line(tree: ExploitTree) -> bool:
    """True when the search has degenerated to one credible line with no
    remaining branching decision: nothing queued (no proposed/executing probes)
    and exactly one live leaf that CANNOT expand further (depth-capped or
    already fully expanded). LATS then hands that obvious line back to legacy
    ReAct rather than keep the tree machinery running (§5.4 EXIT collapse).

    A lone leaf that can still expand is NOT a collapse — LATS deepens it (that
    is the §10 hot-branch behavior), so we only collapse when there is genuinely
    nothing left to branch on.
    """
    if tree.rollouts < 1:
        return False
    for n in tree.nodes.values():
        if n.status in ("proposed", "executing"):
            return False
    leaves = _open_leaves(tree)
    return len(leaves) == 1 and not _can_expand(leaves[0])


def _tree_exhausted(tree: ExploitTree) -> bool:
    """No proposed/executing probes remain and nothing is expandable."""
    for n in tree.nodes.values():
        if n.status in ("proposed", "executing"):
            return False
    return not any(_can_expand(n) for n in tree.nodes.values())


def _budget_hit(tree: ExploitTree) -> bool:
    return (tree.rollouts >= get_setting("LATS_MAX_ROLLOUTS", 24)
            or len(tree.nodes) >= get_setting("LATS_MAX_TREE_NODES", 60))


# =============================================================================
# TREE BOOKKEEPING (§4)
# =============================================================================

def _new_tree(state: dict, root_children: List[dict]) -> ExploitTree:
    """Seed a fresh tree: a synthetic root plus its candidate-probe children."""
    root = ExploitTreeNode(depth=0, status="evaluated", probe_rationale="root")
    tree = ExploitTree(
        root_id=root.id,
        nodes={root.id: root},
        active_node_id=root.id,
        objective=_objective_of(state),
        attack_path_type=state.get("attack_path_type", "") or "",
        primary_target=(state.get("target_info", {}) or {}).get("primary_target", "") or "",
    )
    for cand in root_children:
        _add_child(tree, root, cand)
    return tree


def _objective_of(state: dict) -> str:
    objs = state.get("conversation_objectives") or []
    idx = state.get("current_objective_index", 0)
    if 0 <= idx < len(objs):
        o = objs[idx]
        # ConversationObjective stores the request in `content` (state.py); keep
        # objective/description as fallbacks for other shapes.
        return (o.get("content") or o.get("objective") or o.get("description") or "") if isinstance(o, dict) else str(o)
    return state.get("original_objective", "") or ""


def _add_child(tree: ExploitTree, parent: ExploitTreeNode, cand: dict,
               prior: str = "normal") -> ExploitTreeNode:
    node = ExploitTreeNode(
        parent_id=parent.id,
        depth=parent.depth + 1,
        tool_name=cand.get("tool_name"),
        tool_args=cand.get("tool_args") or {},
        probe_rationale=cand.get("rationale", "") or cand.get("probe_rationale", ""),
        status="proposed",
    )
    # A boosted prior (operator guidance graft, §21.1) is modeled as a seed
    # visit-0 value so UCT still tries it first but backprop can correct it.
    if prior == "high":
        node.local_value = 0.5
    tree.nodes[node.id] = node
    parent.children.append(node.id)
    return node


def _mutex_safe_subset(kids: List[ExploitTreeNode]) -> List[ExploitTreeNode]:
    """Pick a wave that violates no TOOL_MUTEX_GROUP: at most one tool per
    mutex group. Deferred kids stay `proposed` for a later turn. Dangerous
    tools are NOT excluded — the mark is confirmation-only (§20.3).
    """
    group_of = {}
    for group, tools in TOOL_MUTEX_GROUPS.items():
        for t in tools:
            group_of[t] = group
    wave: List[ExploitTreeNode] = []
    claimed: set = set()
    for k in kids:
        g = group_of.get(k.tool_name)
        if g is not None:
            if g in claimed:
                continue          # defer: another kid already claimed this group
            claimed.add(g)
        wave.append(k)
    return wave


def _wave(wave: List[ExploitTreeNode]) -> dict:
    """Build a ToolPlan-shaped dict from a set of child edges. Dangerous steps
    are allowed; the existing confirmation gate handles the prompt (§20.3)."""
    return {
        "steps": [
            {"tool_name": k.tool_name, "tool_args": k.tool_args or {},
             "reasoning": k.probe_rationale, "_lats_node_id": k.id}
            for k in wave
        ]
    }


def _is_dangerous(node: ExploitTreeNode) -> bool:
    return is_dangerous_call(node.tool_name, node.tool_args)


# =============================================================================
# OBSERVATION SUMMARY / REFLECTION — DETERMINISTIC, no LLM (§20.10).
# =============================================================================

_STATUS_RE = re.compile(r"\b(HTTP/\d\.\d\s+)?([1-5]\d{2})\b")
_TOKENISH_RE = re.compile(r"(token|secret|key|flag|error|exception|traceback|denied|unauthorized|admin)", re.I)


def _summarize(tool_output: Optional[str], cap: int = 200) -> str:
    """Compress tool output to ~`cap` chars, preserving the highest-signal
    tokens (HTTP status, error/leak markers). Deterministic; never an LLM."""
    if not tool_output:
        return ""
    text = str(tool_output).strip()
    # Prefer a line carrying an HTTP status or a signal keyword.
    for line in text.splitlines():
        if _STATUS_RE.search(line) or _TOKENISH_RE.search(line):
            line = line.strip()
            return line[:cap]
    single = " ".join(text.split())
    return single[:cap]


def _reflect(step: dict, analysis: Any) -> str:
    """Legacy one-line lesson for a pruned node when NO response_class is
    available (engine off, or the LLM returned an unrecognized/inconclusive
    label). When a class IS present, _evaluate_wave uses _RC_REFLECTIONS instead."""
    ec = step.get("error_class", "") if step else ""
    verdict = _verdict_for(step, analysis)
    if ec == "application_4xx":
        return "server rejected the probe (auth / WAF / method)"
    if verdict == "blocked":
        return "blocked; vector rejected at the app layer"
    if verdict == "duplicate":
        return "duplicate of a prior probe; no new signal"
    if verdict == "no_progress":
        return "no progress; branch cold"
    summ = _summarize(step.get("tool_output") if step else "", cap=80)
    return f"low value; {summ}" if summ else "low value; branch pruned"


# =============================================================================
# ACTIVATION GATE (§5.1) — cheap pre-gate; the ENTER decision also requires the
# lats_expand assessment to yield >= 2 credible probes (enforced in the hook).
# =============================================================================

def _surface_exists(state: dict) -> bool:
    if state.get("chain_findings_memory"):
        return True
    ti = state.get("target_info", {}) or {}
    return bool(ti.get("vulnerabilities") or ti.get("services") or ti.get("technologies"))


def _already_exploited(state: dict) -> bool:
    """A foothold is already in hand for the current objective."""
    for f in (state.get("chain_findings_memory") or []):
        ft = (f.get("finding_type") if isinstance(f, dict) else "") or ""
        if ft in ("exploit_success", "access_gained", "privilege_escalation",
                  "remote_code_execution", "session_hijacked"):
            return True
    return False


def lats_active(state: dict) -> bool:
    """Cheap pre-gate for whether to ATTEMPT activation this turn (§5.1). The
    actual ENTER also requires the lats_expand assessment to yield >= 2 probes.

    Trigger (Fix B2) — an escalation ladder, any of:
      1. Deep Think fired (the original gate, §20.16 — flag not output): severe,
         and LATS already activates off it.
      2. Productivity score >= LATS_SCORE_THRESHOLD: the churn-aware first
         responder, set just BELOW the Deep Think threshold so LATS engages
         before a full strategic re-plan.
      3. State-growth stall >= LATS_REACTIVATE_STUCK_TURNS: the non-gameable
         floor (observed, not self-reported — no new facts for N turns).
    So LATS re-engages WITHIN an objective, not only on a Deep Think turn. All
    guarded by a re-activation cooldown since the last archive so a freshly
    collapsed tree cannot immediately rebuild the same dead branches."""
    if not get_setting("LATS_ENABLED", False):
        return False
    allowed = get_setting("LATS_ALLOWED_PHASES", ["exploitation"])
    if state.get("current_phase") not in allowed:
        return False
    if not _surface_exists(state):
        return False
    # A mid-chain foothold only stops LATS when explicitly configured. OFF for
    # flag-hunts (default): a foothold is a MEANS to the flag, so it must NOT
    # block LATS from engaging to push the chain through to the objective.
    if get_setting("LATS_STOP_ON_FOOTHOLD", False) and _already_exploited(state):
        return False
    # Re-activation cooldown (does not apply to the first-ever activation, where
    # _lats_last_archive_iter is unset).
    last_archive = state.get("_lats_last_archive_iter")
    if last_archive is not None:
        cooldown = int(get_setting("LATS_REACTIVATE_COOLDOWN", 4))
        if int(state.get("current_iteration", 0) or 0) - int(last_archive) < cooldown:
            return False
    # 1. Deep Think fired.
    if bool(state.get("deep_think_ran_this_turn")):
        return True
    # 2. Productivity score crossed the LATS threshold (churn-aware, just below
    #    Deep Think's).
    score_obj = state.get("_last_productivity_score") or {}
    try:
        score = float(score_obj.get("score", 0.0) or 0.0)
    except (TypeError, ValueError, AttributeError):
        score = 0.0
    if score >= float(get_setting("LATS_SCORE_THRESHOLD", 4.0)):
        return True
    # 3. Observed state-growth stall floor.
    stuck_k = int(get_setting("LATS_REACTIVATE_STUCK_TURNS", 3))
    return int(state.get("_iterations_since_state_grew", 0) or 0) >= stuck_k


def lats_is_driving(state: dict) -> bool:
    """True when a LATS tree is live AND in drive mode (non-shadow). Deep Think
    yields to LATS on these turns (Fix C): the tree search IS the re-planning,
    and LATS's probes must not pin productivity 'critical' and bypass the Deep
    Think cooldown into a fire-every-turn loop. Shadow mode never drives."""
    return (
        bool(get_setting("LATS_ENABLED", False))
        and not bool(get_setting("LATS_SHADOW_MODE", False))
        and bool(state.get("_exploit_tree"))
    )


def _host_port(t: str):
    """Split a target string into (host, port). Strips scheme + trailing
    slash(es) + surrounding whitespace and lowercases; `port` is '' when absent.
    Only a trailing `:<digits>` is treated as a port (so paths / IPv6 are left
    on the host side rather than mis-split)."""
    s = (t or "").strip().lower()
    for scheme in ("https://", "http://"):
        if s.startswith(scheme):
            s = s[len(scheme):]
            break
    s = s.rstrip("/")
    if ":" in s:
        host, _, port = s.rpartition(":")
        if host and port.isdigit():
            return host, port
    return s, ""


def _same_target(a: str, b: str) -> bool:
    """True if a and b denote the SAME target. Host identity must match; a
    MISSING port matches any port, because recon adds the port to
    `primary_target` over the run (`lab-x` becomes `lab-x:8002`) — but two
    DIFFERENT explicit ports are a real change. Scheme / trailing-slash / case
    are ignored. This is what stops the residual `target_change` false reset
    (XBEN-064: scheme/slash; XBEN-066: bare host vs host:8002)."""
    ha, pa = _host_port(a)
    hb, pb = _host_port(b)
    if ha != hb:
        return False
    if pa and pb and pa != pb:
        return False
    return True


def _reset_reasons(state: dict, tree: ExploitTree) -> List[str]:
    """The §20.6 reset conditions TRUE this turn, each EMPTY-GUARDED: a blank /
    empty live value is 'unknown, not changed' and never counts — the live
    phase / skill / objective / target all transiently blank as the agent
    re-derives them each turn, and comparing a stamped truthy value against a
    transient '' was the dominant false-reset source. Pure: no state mutation.
    The debounce + final decision live in `_lats_should_reset`."""
    reasons: List[str] = []
    if state.get("task_complete"):
        reasons.append("task_complete")
    # Phase left the allowed set — but an empty phase is a re-derivation gap, not
    # a genuine exit.
    phase = state.get("current_phase") or ""
    if phase and phase not in get_setting("LATS_ALLOWED_PHASES", ["exploitation"]):
        reasons.append("phase_left")
    # Foothold-in-hand. OFF by default on flag-hunts (a foothold is a MEANS, not
    # the objective — resetting here loses the tree before it reaches the flag).
    if get_setting("LATS_STOP_ON_FOOTHOLD", False) and _already_exploited(state):
        reasons.append("already_exploited")
    # Objective advanced — empty live objective is a re-derivation gap.
    live_obj = (_objective_of(state) or "").strip()
    if tree.objective and live_obj and tree.objective.strip() != live_obj:
        reasons.append("objective_changed")
    # Skill switched — empty live attack_path_type is a transition blank.
    live_apt = state.get("attack_path_type", "") or ""
    if tree.attack_path_type and live_apt and tree.attack_path_type != live_apt:
        reasons.append("skill_switch")
    # Primary target changed — host identity, port-lenient (see _same_target).
    cur_target = (state.get("target_info", {}) or {}).get("primary_target", "") or ""
    if tree.primary_target and cur_target and not _same_target(tree.primary_target, cur_target):
        reasons.append("target_change")
    return reasons


def _lats_should_reset(state: dict, tree: ExploitTree) -> bool:
    """DEBOUNCED archive-and-restart decision for a live tree (§20.6). A reset
    condition (empty-guarded, see `_reset_reasons`) must hold for
    `LATS_RESET_DEBOUNCE` CONSECUTIVE turns before the tree is torn down, so a
    one-turn jitter blip (a transient blank, a phase dip that reverts, a skill
    flip-and-revert) never nukes a healthy tree. `task_complete` is exempt
    (immediate — the run is ending). Mutates `_lats_reset_streak`; call at most
    once per hook."""
    reasons = _reset_reasons(state, tree)
    if not reasons:
        state["_lats_reset_streak"] = 0
        return False
    if "task_complete" in reasons:
        state["_lats_reset_streak"] = 0
        return True
    streak = int(state.get("_lats_reset_streak", 0) or 0) + 1
    need = int(get_setting("LATS_RESET_DEBOUNCE", 2))
    if streak >= need:
        state["_lats_reset_streak"] = 0
        logger.info("[lats] reset after debounce (held %d turns): %s", streak, reasons)
        return True
    state["_lats_reset_streak"] = streak
    logger.debug("[lats] reset condition pending %d/%d: %s", streak, need, reasons)
    return False


# =============================================================================
# EXPAND (§20.9) — LATS's OWN structured probe generator on the single agent
# model. NEVER reads deep_think_result (§20.16). node=None -> root assessment.
# =============================================================================

def _phase_allowed_tools(state: dict) -> set:
    tpm = get_setting("TOOL_PHASE_MAP", {}) or {}
    phase = state.get("current_phase", "exploitation")
    return {name for name, phases in tpm.items() if phase in phases}


# --- Tool arg-schema awareness (Fix #1: the expand LLM kept inventing keys like
# url/target/flags instead of each tool's real schema, so its probes bounced off
# the tool layer with tool_internal_error). The schema is fed into the prompt AND
# enforced by a deterministic pre-flight validator that drops malformed probes. -

def _tool_arg_keys(tool_name: str) -> List[str]:
    """The valid tool_args keys for a tool, parsed from its registry
    args_format (first key = primary/required). Empty list = the tool takes no /
    freeform args, so no key check applies."""
    try:
        from prompts.tool_registry import visible_registry
    except Exception:
        return []
    af = (visible_registry().get(tool_name, {}) or {}).get("args_format", "") or ""
    return re.findall(r'"([a-zA-Z_][a-zA-Z0-9_]*)"\s*:', af)


def _probe_args_valid(tool_name: str, args: dict) -> bool:
    """Deterministic pre-flight arg check. A probe must include the tool's PRIMARY
    key (e.g. `args` for execute_*, `id` for proxy_get, `command` for kali_shell);
    this catches the LLM inventing url/target/flags/depth keys. Then a few
    tool-specific MECHANICAL guards drop invocations that pass the key check but
    would bounce off the tool at runtime (a wasted rollout) — e.g. ffuf without
    its required FUZZ keyword. Tools with no schema pass the key check but still
    get the mechanical guards."""
    args = args or {}
    keys = _tool_arg_keys(tool_name)
    if keys and keys[0] not in args:
        return False
    a = str(args.get("args", "") or "")
    # execute_ffuf REQUIRES the literal FUZZ keyword somewhere in the args, else
    # it exits immediately with "Encountered error(s)" (12 such failures observed).
    if tool_name == "execute_ffuf" and "FUZZ" not in a:
        return False
    return True


# Compact per-tool usage cheatsheet for the expand step. The lean expand context
# drops the full ~22K tool-inventory docs (which teach valid flags), so the LLM
# guessed flags and ~13% of probes bounced off the tool layer (ffuf without FUZZ,
# arjun --get, katana -silent, curl ---, kali_shell for uninstalled tools). These
# one-liners restore just the flag-correctness guidance, not the bulk.
_EXPAND_TOOL_HINTS = {
    "execute_ffuf":   "put the literal FUZZ keyword in the URL (e.g. -u http://h/FUZZ -w <wordlist>); use -mc/-fc to match/filter status, -t for threads. NO -silent (not an ffuf flag).",
    "execute_arjun":  "params: -u URL, -m GET|POST (NOT --get), -oT/-oJ for output. Does NOT accept -c/--threads/--timeout.",
    "execute_katana": "crawl: -u URL, -jc (JS), -d <depth>, -o <file>. NO -silent / -kf.",
    "execute_curl":   "raw curl args only; never a bare `---`, and avoid -x unless a proxy is intended (it can hang on a password prompt). For piping/grep, use execute_code instead.",
    "execute_code":   "Python (requests/socket/pwntools). Keep it FAST (<60s) — no long brute-force loops or sleeps; execution is killed at 120s.",
    "kali_shell":     "only tools actually installed in Kali; do NOT assume niche tools exist (e.g. flask-unsign) — use execute_code for those.",
}


def _expand_tool_hints(allowed_tools: set) -> str:
    """One-line correct-usage hints for the allowed tools that commonly get
    mis-invoked, so the expand step proposes runnable probes instead of guessing
    flags. Empty when none of the hinted tools are allowed."""
    lines = [f"  {name}: {_EXPAND_TOOL_HINTS[name]}"
             for name in sorted(allowed_tools) if name in _EXPAND_TOOL_HINTS]
    return "\n".join(lines)


def _tool_schema_block(allowed_tools: set) -> str:
    """Render each allowed tool's arg schema for the expand prompt so the model
    emits correctly-shaped tool_args."""
    try:
        from prompts.tool_registry import visible_registry
        _reg = visible_registry()
    except Exception:
        _reg = {}
    lines = []
    for name in sorted(allowed_tools):
        af = (_reg.get(name, {}) or {}).get("args_format", "") if _reg else ""
        lines.append(f"  {name}: tool_args = {{{af}}}" if af else f"  {name}: tool_args = {{}}")
    return "\n".join(lines)


def _parse_expand_response(text: str, allowed_tools: set, branching: int,
                           existing_keys: Optional[set] = None) -> List[dict]:
    """Pure parser + validator for a structured expand response. Returns up to
    `branching` probes, each {tool_name, tool_args, rationale}, dropping any probe
    whose tool_name is missing / not phase-allowed, or whose tool_args are the
    wrong shape for that tool (§20.9, Fix #1).

    HARD dedup: any probe whose normalized key is already in `existing_keys` (the
    probes already in the tree) or was already emitted earlier in THIS response is
    dropped. The soft "do not repeat" prompt list was capped and advisory; this is
    the enforced guarantee, so a deep tree can no longer re-run a byte-identical
    probe just because it scrolled past the prompt's cap."""
    if not text:
        return []
    payload = _extract_json(text)
    if payload is None:
        return []
    raw = payload.get("probes") if isinstance(payload, dict) else payload
    if not isinstance(raw, list):
        return []
    seen: set = set(existing_keys or ())
    probes: List[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        tn = item.get("tool_name")
        if not tn or (allowed_tools and tn not in allowed_tools):
            continue                      # off-registry / not phase-allowed -> drop
        args = item.get("tool_args")
        if args is not None and not isinstance(args, dict):
            continue
        if not _probe_args_valid(tn, args or {}):
            continue                      # malformed args (wrong keys) -> drop pre-flight
        key = _probe_dedup_key(tn, args or {})
        if key in seen:
            continue                      # HARD dedup: already in tree or this batch
        seen.add(key)
        probes.append({
            "tool_name": tn,
            "tool_args": args or {},
            # Defensive bound only (guards against a malformed giant LLM string
            # bloating the streamed snapshot). The UI shows this in full and
            # prompt renderers re-truncate to ~30-40 chars, so a real rationale
            # is never cut mid-sentence in the card / inspector title.
            "rationale": str(item.get("rationale", "") or "")[:1000],
        })
        if len(probes) >= branching:
            break
    return probes


def _extract_json(text: str) -> Optional[Any]:
    """Best-effort JSON extraction from an LLM string (handles fenced blocks)."""
    text = text.strip()
    if "```" in text:
        m = re.search(r"```(?:json)?\s*(.*?)```", text, re.S)
        if m:
            text = m.group(1).strip()
    try:
        return json.loads(text)
    except Exception:
        # Fall back to the first {...} or [...] span.
        for opener, closer in (("{", "}"), ("[", "]")):
            i, j = text.find(opener), text.rfind(closer)
            if 0 <= i < j:
                try:
                    return json.loads(text[i:j + 1])
                except Exception:
                    continue
    return None


# --- Expand INPUT CONTRACT: the forward-looking situational context an exploit-
# probe generator needs. Reused by the seed AND every node expansion so LATS
# reasons from the same facts a normal think step does (recon surface + findings
# + failures + prior trees + Deep Think's HYPOTHESES) — never Deep Think's single
# recommended plan, which would linearize the tree. All compact/capped so a deep
# tree's expand prompt stays bounded.

# Cross-tree memory (W7): which response classes are worth CARRYING between trees.
# LEADS = a live/progressing vector the next tree should BUILD ON. DEAD = a class
# confirmed negative on that target — the next tree must NOT re-attempt it. Every
# other class (auth_required, waf_block, wrong_method, ... — a transient
# precondition, not a verdict on the vector) is deliberately NOT carried, and a
# diagnostic/unclassified node is NEVER carried (it never reached the app, so it
# proves nothing — this is the rule that stops a curl-error probe from wrongly
# "ruling out" a live vector).
_LEAD_CLASSES = frozenset({
    "exploit_confirmed", "oob_callback", "error_leak", "outbound_fetch",
    "boolean_differential", "info_disclosure", "time_differential",
    "reflected_unsanitized", "partial_filter_bypass", "server_error_5xx",
    "filter_blacklist", "encoding_normalization",
})
_DEAD_CLASSES = frozenset({
    "dead_endpoint", "filter_whitelist", "benign_no_signal", "geo_legal_block", "duplicate",
})


def _target_sig(node: ExploitTreeNode) -> str:
    """Short, READABLE 'what was targeted' from tool_args (endpoint + first param),
    so a cross-tree digest entry says `error_leak @ /total_loan_payments?principal`
    instead of a bare tool name. Falls back to the tool name; never raises."""
    ta = node.tool_args or {}
    if isinstance(ta, dict):
        raw = str(ta.get("args") or ta.get("url") or ta.get("command") or ta.get("code") or "")
    else:
        raw = str(ta)
    m = re.search(r"(/[\w./%~-]+)(\?[\w%.\[\]-]+=?)?", raw)   # path + first param key
    sig = (m.group(0) if m else raw).strip()
    sig = " ".join(sig.split())[:60]
    return sig or (node.tool_name or "?")


def _tree_leads_and_dead(tree: "ExploitTree"):
    """Extract the SEMANTIC knowledge a finished tree earned: confirmed LEADS (with
    the node's actionable reflection) and confirmed-DEAD class@target pairs. Deduped
    within the tree by (response_class, target). Excludes proposed/diagnostic/
    unclassified nodes so nothing that never reached the app is recorded."""
    leads: dict = {}   # (cls, sig) -> reflection
    dead: dict = {}    # (cls, sig) -> None
    for n in tree.nodes.values():
        if n.parent_id is None or n.status == "proposed":
            continue
        rc = n.response_class or ""
        if not rc or is_diagnostic_failure(n.error_class or ""):
            continue
        key = (rc, _target_sig(n))
        if rc in _LEAD_CLASSES:
            leads.setdefault(key, (n.reflection or ""))
        elif rc in _DEAD_CLASSES:
            dead.setdefault(key, None)
    lead_lines = [f"{rc} @ {sig}" + (f" ({why})" if why else "")
                  for (rc, sig), why in leads.items()]
    dead_lines = [f"{rc} @ {sig}" for (rc, sig) in dead]
    return lead_lines, dead_lines


def _tree_digest_entry(tree: "ExploitTree", outcome: str) -> str:
    """One compact per-tree narrative line: outcome + where the best line ended up,
    rendered SEMANTICALLY (the leaf's class @ target) rather than as tool names. The
    reusable leads/ruled-out knowledge lives in the merged _lats_leads/_lats_dead
    stores, not here."""
    succeeded = any(n.exploit_succeeded for n in tree.nodes.values())
    tag = "FOOTHOLD" if succeeded else outcome
    leaf = tree.nodes.get(tree.best_terminal_id) if tree.best_terminal_id else None
    if leaf is not None and leaf.tool_name:
        best = f"{leaf.response_class or leaf.verdict or leaf.status} @ {_target_sig(leaf)}"
    else:
        best = " -> ".join(_trajectory_labels(tree)) or "n/a"
    return f"[{tag}] obj={(tree.objective or '')[:50]} | best: {best}"


def _append_tree_digest(state: dict, tree: "ExploitTree", outcome: str) -> None:
    """Persist a finished tree's knowledge so every subsequent LATS tree inherits it
    (survives execution_trace eviction). Three append-only stores:
      1. _lats_tree_digest  — one narrative line per tree (outcome + best line).
      2. _lats_leads/_lats_dead — the SEMANTIC class@target knowledge, MERGED and
         deduped across ALL trees, so tree N sees a single clean union of every
         prior tree's confirmed leads and confirmed-dead classes (not N repetitive
         per-tree blobs).
      3. _lats_probe_ledger — HARD byte-identical dedup keys (unchanged)."""
    entry = _tree_digest_entry(tree, outcome)
    hist = list(state.get("_lats_tree_digest") or [])
    hist.append(entry)
    cap = int(get_setting("LATS_DIGEST_MAX", 8))
    state["_lats_tree_digest"] = hist[-cap:]

    # Merge this tree's leads/dead into the run-level, deduped knowledge stores.
    lead_lines, dead_lines = _tree_leads_and_dead(tree)
    kcap = cap * 4   # bound the merged lists even across many trees
    state["_lats_leads"] = list(dict.fromkeys((state.get("_lats_leads") or []) + lead_lines))[-kcap:]
    state["_lats_dead"] = list(dict.fromkeys((state.get("_lats_dead") or []) + dead_lines))[-kcap:]

    # Run-level probe ledger (§3 cross-tree HARD dedup). The digest above is the
    # soft, human-readable hint the next tree READS; this is the enforced
    # guarantee the next tree's expand is FILTERED by, so a later tree can no
    # longer re-run a byte-identical probe an earlier tree already tried.
    # Executed-only (status != "proposed") so a prior tree's UNtried frontier
    # probe stays legitimately explorable; the conservative key means only
    # identical probes collapse (distinct payloads survive — same as within-tree).
    ledger = list(state.get("_lats_probe_ledger") or [])
    for n in tree.nodes.values():
        if n.parent_id is not None and n.tool_name and n.status != "proposed":
            ledger.append(_probe_dedup_key(n.tool_name, n.tool_args))
    lcap = int(get_setting("LATS_PROBE_LEDGER_MAX", 400))
    # dedup preserving order, keep the most recent lcap keys
    state["_lats_probe_ledger"] = list(dict.fromkeys(ledger))[-lcap:]


def _prior_tree_summaries(state: dict, cap: int = 6) -> str:
    """Accumulated prior-tree knowledge for the next tree: the run-level, deduped
    CONFIRMED LEADS (build on these) and RULED-OUT class@target pairs (do NOT
    re-attempt), plus a short per-tree narrative. Falls back to scraping
    execution_trace's carried-forward summaries for backward compatibility."""
    hist = state.get("_lats_tree_digest") or []
    leads = state.get("_lats_leads") or []
    dead = state.get("_lats_dead") or []
    if hist or leads or dead:
        parts: List[str] = []
        if leads:
            parts.append("CONFIRMED LEADS (build on these): " + "; ".join(leads[-12:]))
        if dead:
            parts.append("RULED OUT (dead class@target — do NOT re-attempt): "
                         + "; ".join(dead[-16:]))
        if hist:
            parts.append("Per-tree: " + " | ".join(hist[-cap:]))
        return "\n".join(parts)
    trace = state.get("execution_trace") or []
    sums = [str(s.get("tool_output", ""))[:900]
            for s in trace
            if isinstance(s, dict) and s.get("tool_name") == "lats_search"]
    return "\n---\n".join(sums[-2:]) if sums else ""


def _full_think_context(state: dict) -> str:
    """LEAN GROUNDING CONTEXT: the minimal-but-complete slice of think-node
    context the expand step needs to propose CORRECT probes — nothing more.

    A probe is "correct" when it (a) hits a REAL target, (b) uses the RIGHT
    technique for the vuln class, (c) is EXECUTABLE, (d) doesn't repeat a dead
    end, (e) stays in scope. Each requirement maps to exactly one block below.
    Deliberately NOT a think-node clone: the full 22k tool-inventory docs, the
    switchable skill menu, phase definitions, and todo/qa/objective bookkeeping
    are excluded because none of them change which probe is right (the arg
    schema — supplied separately via _tool_schema_block in the system message —
    already makes probes executable; the skill workflow already carries the
    class technique).

    Blocks (each guarded — a failure in one never breaks expand):
      1. Attack-chain context — rendered execution trace (real endpoints,
         params, observations). THE grounding source: WHERE to probe. (a)
      2. target_info — tech/service context. (a)
      3. Rules of Engagement / scope guardrail. (e)
      4. Active built-in skill WORKFLOW — the class's technique + payload
         templates, split out of get_phase_tools so we get the playbook WITHOUT
         the 22k tool-inventory bulk. HOW to probe. (b)
      5. Agent/Chat skills catalog — load-on-demand specialist techniques. (b)

    Lazy imports throughout (lats is imported by think_node — avoids a cycle).
    """
    parts: List[str] = []
    phase = state.get("current_phase", "exploitation") or "exploitation"
    apt = state.get("attack_path_type", "") or ""

    # 1. Attack-chain context (execution trace → the real discovered surface).
    #    WHERE to probe — the whole reason for the grounding fix.
    try:
        from state import format_chain_context
        win = int(get_setting("LATS_CONTEXT_WINDOW", 12))
        cc = format_chain_context(
            chain_findings=state.get("chain_findings_memory") or [],
            chain_failures=state.get("chain_failures_memory") or [],
            chain_decisions=state.get("chain_decisions_memory") or [],
            execution_trace=state.get("execution_trace") or [],
            recent_iterations=win,
        )
        if cc and cc.strip():
            parts.append("## Attack-chain so far (what the agent has actually done — probe THESE real endpoints/params)\n" + cc)
    except Exception as _e:
        logger.debug("[lats full-ctx] chain_context skipped: %s", _e)

    # 2. target_info (tech/service context)
    try:
        ti = state.get("target_info") or {}
        if ti:
            parts.append("## Target info\n" + json.dumps(ti)[:2500])
    except Exception:
        pass

    # 3. Rules of Engagement / scope guardrail (stay in bounds)
    roe_at = None
    try:
        from prompts.base import build_roe_prompt_section
        roe = build_roe_prompt_section()
        if roe and roe.strip():
            roe_at = len(parts)
            parts.append(roe.strip())
    except Exception:
        pass

    # 4. Active built-in skill WORKFLOW ONLY (technique + payload templates for
    #    the vuln class). Uses the shared module-level builder — same playbook
    #    the think node gets from get_phase_tools, minus the 22k tool inventory.
    try:
        from prompts import build_builtin_skill_workflow
        from project_settings import get_allowed_tools_for_phase
        allowed_for_phase = get_allowed_tools_for_phase(phase)
        wf = build_builtin_skill_workflow(
            apt,
            allowed_for_phase,
            is_statefull=(str(get_setting('POST_EXPL_PHASE_TYPE', 'statefull')) == 'statefull'),
            execution_trace=state.get("execution_trace") or [],
        )
        if wf:
            parts.append("## Active attack-skill workflow (follow this technique when choosing probes)\n"
                         + "\n\n".join(wf))
            # A plugin-approved rewrite of the playbook must not be the last word on
            # scope: as in the think node, the RoE section then follows it.
            from prompts.skill_part_seam import applied_skill_workflow
            if roe_at is not None and (applied_skill_workflow.get() or {}).get("revision", 1) > 1:
                parts.append(parts.pop(roe_at))
    except Exception as _e:
        logger.debug("[lats full-ctx] skill workflow skipped: %s", _e)

    # 5. Agent/Chat skills catalog (load-on-demand markdown skills)
    try:
        from orchestrator_helpers.skill_loader import list_skills
        sk = list_skills() or []
        if sk:
            cat = "\n".join(f"- {s.get('id')}: {s.get('description', '')}" for s in sk[:80])
            parts.append("## Available Agent/Chat skills (load on demand for deeper technique)\n" + cat)
    except Exception:
        pass

    return "\n\n".join(parts)


def _situational_context(state: dict) -> str:
    """Recon surface + confirmed findings + failed dead-ends + prior LATS trees,
    rendered compactly. This is the awareness the expand step was missing.

    When LATS_FULL_CONTEXT is on, PREPEND the lean grounding context (chain
    context, target_info, RoE, active skill workflow, skills catalog) so the
    expand step can propose grounded, correct probes — the compressed block
    below then adds the LATS-specific findings/failures/prior-tree deltas on
    top."""
    full = _full_think_context(state) if get_setting("LATS_FULL_CONTEXT", True) else ""
    parts: List[str] = []
    ti = state.get("target_info", {}) or {}
    surface = []
    for key in ("primary_target", "hosts", "services", "technologies",
                "endpoints", "parameters", "vulnerabilities"):
        v = ti.get(key)
        if v:
            surface.append(f"{key}={json.dumps(v)[:280]}")
    if surface:
        parts.append("Recon surface:\n  " + "\n  ".join(surface))

    findings = state.get("chain_findings_memory") or []
    flines = []
    for f in findings[-8:]:
        if isinstance(f, dict):
            desc = str(f.get("description") or f.get("content") or "")[:140]
            flines.append(f"- {f.get('finding_type', 'finding')}: {desc}")
    if flines:
        parts.append("Confirmed so far:\n" + "\n".join(flines))

    failures = state.get("chain_failures_memory") or []
    xlines = []
    for f in failures[-8:]:
        if isinstance(f, dict):
            desc = str(f.get("description") or f.get("reason") or f.get("content") or "")[:140]
            if desc:
                xlines.append(f"- {desc}")
    if xlines:
        parts.append("Tried and FAILED (do not repeat these dead ends):\n" + "\n".join(xlines))

    prior = _prior_tree_summaries(state)
    if prior:
        parts.append("Prior LATS searches this run (build on, do not re-explore):\n" + prior)

    compressed = "\n\n".join(parts) if parts else \
        "(no findings yet; propose entry probes from the objective and recon surface)"
    # Full-context parity (grounding): the full think-node context leads, the
    # LATS-specific deltas (findings/failures/prior-trees) follow.
    if full and full.strip():
        return full + "\n\n## LATS deltas\n" + compressed
    return compressed


def _skill_methodology(state: dict) -> str:
    """The ACTIVE attack-path skill's methodology (the exploitation playbook for
    the current vuln class), reused from the same builder the think step uses so
    LATS proposes probes that follow proven technique, not ad-hoc guesses.
    Guarded + empty when unavailable so a missing skill never breaks expand."""
    apt = state.get("attack_path_type", "") or ""
    if not apt:
        return ""
    try:
        from prompts.base import build_attack_path_behavior
        return (build_attack_path_behavior(apt) or "").strip()
    except Exception:
        return ""


def _deep_think_seed_block(state: dict) -> str:
    """Deep Think's competing hypotheses + attack vectors as ROOT branching
    material (each hypothesis carries a probe idea). Excludes its recommended_
    approach / priority_order on purpose — following that single line would
    collapse the tree. Empty unless Deep Think fired this turn."""
    hints = state.get("_lats_deep_think_hints") or {}
    if not hints:
        return ""
    lines = []
    for h in (hints.get("hypotheses") or [])[:5]:
        if not isinstance(h, dict):
            continue
        hyp = str(h.get("hypothesis", ""))[:160]
        probe = str(h.get("probe", ""))[:160]
        lines.append(f"- Hypothesis: {hyp}" + (f"\n  Probe idea: {probe}" if probe else ""))
    vectors = [str(v)[:80] for v in (hints.get("attack_vectors") or [])[:8]]
    block = ""
    if lines:
        block = ("Deep Think just proposed these competing hypotheses — turn each "
                 "into a CONCRETE probe as a distinct branch:\n" + "\n".join(lines))
    if vectors:
        block += ("\n" if block else "") + "Attack vectors identified: " + ", ".join(vectors)
    return block


def _render_path(tree: "ExploitTree", node: ExploitTreeNode) -> str:
    """Root-to-node trajectory: each ancestor probe with its verdict + short
    observation, so an extension sees the WHOLE line (not just the parent)."""
    chain: List[str] = []
    nid: Optional[str] = node.id
    guard = 0
    while nid is not None and guard < 64:
        guard += 1
        n = tree.nodes.get(nid)
        if n is None:
            break
        if n.parent_id is not None:               # skip synthetic root
            tag = n.response_class or n.verdict or n.error_class or n.status
            obs = (" | " + n.observation_summary[:80]) if n.observation_summary else ""
            chain.append(f"{_node_label(n)} [{tag}]{obs}")
        nid = n.parent_id
    chain.reverse()
    return " -> ".join(chain) if chain else "(root)"


def _probe_dedup_key(tool_name: str, tool_args: Any) -> str:
    """Stable key for cross-branch / within-batch dedup: tool name + the
    whitespace-normalized primary argument. Deliberately CONSERVATIVE - it
    normalizes only whitespace, never case or payload content, so genuinely
    different probes (a different file to read, param, engine, or bypass char)
    stay DISTINCT and only byte-identical probes collapse. This is what lets an
    LFI vector be enumerated exhaustively (etc/passwd, etc/hosts, flag, ...)
    without those being mistaken for repeats, while `post.php?id=flag` proposed
    twice is caught."""
    ta = tool_args or {}
    if isinstance(ta, dict):
        raw = (ta.get("args") or ta.get("code") or ta.get("url")
               or ta.get("command") or json.dumps(ta, sort_keys=True))
    else:
        raw = str(ta)
    norm = " ".join(str(raw).split())
    return f"{tool_name}{norm}"


def _existing_probe_keys(tree: "ExploitTree") -> set:
    """Every probe already in the tree as dedup keys, UNCAPPED. The soft prompt
    list (`_existing_probes`) is capped for readability and can miss probes once
    a tree grows past the cap; this set does not, so the HARD dedup in
    `_parse_expand_response` still blocks a re-proposal of any earlier probe no
    matter how deep the tree is."""
    return {
        _probe_dedup_key(n.tool_name, n.tool_args)
        for n in tree.nodes.values()
        if n.parent_id is not None and n.tool_name
    }


def _existing_probes(tree: "ExploitTree", cap: int = 40) -> str:
    """Compact signatures of probes already in the tree, so expand does not
    re-propose them (cross-branch dedup). Shows the MOST RECENT `cap` probes -
    on a deep tree (> cap probe-nodes) the freshest branches are the ones an
    extension is most likely to collide with, and the exhaustive, uncapped
    guarantee is enforced separately in `_parse_expand_response` via
    `_existing_probe_keys`, so this list is now just a readability hint."""
    sigs = [f"- {n.tool_name} {str(n.tool_args or {})[:60]}"
            for n in tree.nodes.values()
            if n.parent_id is not None and n.tool_name]
    return "\n".join(sigs[-cap:])


def _expand_prompt_messages(state: dict, node: Optional[ExploitTreeNode],
                            allowed_tools: set, branching: int,
                            tree: Optional["ExploitTree"] = None) -> list:
    """Build the messages for a structured expand call, now grounded in the full
    situational context (recon/findings/failures/prior-trees), the Deep Think
    hypotheses (seed), and the root-to-node path + tree dedup (extension)."""
    objective = _objective_of(state)
    phase = state.get("current_phase", "exploitation")
    tool_schema = _tool_schema_block(allowed_tools) if allowed_tools else "  (any tool)"
    tool_hints = _expand_tool_hints(allowed_tools) if allowed_tools else ""
    # Dynamic width: the ROOT uses the full width (fan out across entry vectors);
    # EXTENSIONS pick a count in [lo, branching] by how branchy the node genuinely
    # is, so a narrow node is not padded up to the cap (padding = wasted rollouts +
    # strained, badly-flagged probes).
    lo = min(branching, max(3, branching // 2))
    situational = _situational_context(state)
    methodology = _skill_methodology(state)
    method_block = (f"\n\nMETHODOLOGY (active attack-path skill — follow this playbook "
                    f"when choosing probes):\n{methodology}" if methodology else "")

    if node is None or node.tool_name is None:
        seed = _deep_think_seed_block(state)
        branch = f"\n\n{seed}" if seed else ""
        ask = (f"Assess the situation above and propose {branching} DISTINCT entry "
               f"probes — USE THE FULL WIDTH at the root, grounded in the recon "
               f"surface and findings: FAN OUT across the different credible vuln "
               f"classes / entry points the surface offers, do not commit to one.")
    else:
        path = _render_path(tree, node) if tree is not None else _node_label(node)
        rc = node.response_class or ""
        tag = rc or node.verdict or node.error_class or node.status
        lesson = f"\n  Lesson: {node.reflection}" if node.reflection else ""
        branch = (
            f"\n\nCurrent branch you are extending:\n"
            f"  Path: {path}\n"
            f"  Extending: {node.tool_name} {json.dumps(node.tool_args or {})} [{tag}]\n"
            f"  Observation: {node.observation_summary or '(none)'}"
            f"{lesson}"
        )
        # Reflection-conditioned expansion: when the node carries a recognized
        # response_class, its directive dictates what THIS wave must contain (the
        # move that converts the lead), replacing the generic "pivot if blocked".
        directive = _RC_EXPAND_DIRECTIVES.get(rc)
        if directive:
            ask = (f"This node was classified `{rc}`. {directive}\n\n"
                   f"Propose between {lo} and {branching} such probes, most-promising "
                   f"first. Do NOT pad to {branching}: {lo} strong, distinct probes beat "
                   f"{branching} with filler.")
        else:
            ask = (f"Propose between {lo} and {branching} DISTINCT follow-up probes that "
                   f"build on this line. DECIDE THE COUNT by how many materially-different, "
                   f"credible continuations THIS node genuinely offers — pivot if blocked, "
                   f"deepen if it made progress. Do NOT pad to {branching}: {lo} strong, "
                   f"distinct probes beat {branching} with filler. Return fewer than {lo} "
                   f"only if this line is genuinely near-dead.")

    existing = _existing_probes(tree) if tree is not None else ""
    dedup = (f"\n\nAlready in the tree — propose DIFFERENT probes, do not repeat:\n{existing}"
             if existing else "")

    system = (
        "You are the expansion step of a value-guided exploit-path search. "
        "Return ONLY strict JSON of the form "
        '{\"probes\": [{\"tool_name\": <one of the tools below>, '
        '\"tool_args\": {..}, \"rationale\": \"why this probe advances the exploit\"}]}. '
        "CRITICAL: tool_args MUST use EXACTLY the argument keys shown for the chosen "
        "tool below. Do NOT invent keys like url/target/flags/depth/silent — most "
        "tools take a single \"args\" string holding the raw CLI arguments (without "
        "the tool name). Allowed tools and their required tool_args schema:\n"
        f"{tool_schema}\n"
        + (f"Tool usage (get the flags right — malformed probes are wasted):\n{tool_hints}\n"
           if tool_hints else "")
        + f"The NUMBER of probes is YOUR decision (never more than {branching}): match "
        f"it to how many materially-different, credible directions this specific step "
        f"genuinely offers — different vuln classes, endpoints, parameters, template/DB "
        f"engines, or bypass techniques. Use the full width when the step truly "
        f"branches; return fewer when it does not. NEVER pad with near-duplicate "
        f"variations to hit a number — a few strong, distinct probes beat many filler "
        f"ones (filler probes just waste rollouts). Order them most-promising first. "
        "Each must be a concrete, executable probe (never a plan or a question). "
        "Ground every probe in the situation below; do not repeat failed dead ends."
    )
    user = (
        f"Objective: {objective}\n"
        f"Phase: {phase}\n\n"
        f"SITUATION:\n{situational}"
        f"{method_block}"
        f"{branch}\n\n"
        f"{ask}"
        f"{dedup}"
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": user},
    ]


async def lats_expand(llm: Any, state: dict, node: Optional[ExploitTreeNode],
                      tree: Optional["ExploitTree"] = None) -> List[dict]:
    """Generate up to LATS_BRANCHING candidate probes via ONE structured call on
    the single agent model. node=None -> root/situation assessment (ENTER);
    a real node -> extend that branch. Returns validated, phase-valid probes.

    Grounded in the full situational context (recon surface + findings + failures
    + prior LATS trees) and, on the seed, Deep Think's competing hypotheses +
    attack vectors. It deliberately does NOT consume Deep Think's recommended_
    approach / priority_order — using those as a plan would linearize the tree
    (the correctly-scoped §20.16)."""
    from orchestrator_helpers.llm_retry import retry_llm_call

    branching = int(get_setting("LATS_BRANCHING", 3))
    allowed = _phase_allowed_tools(state)
    messages = _expand_prompt_messages(state, node, allowed, branching, tree=tree)
    # [TEMP DIAGNOSTIC] dump the REAL expand prompt so we can PROVE what context
    # LATS actually receives (situational grounding, branch propagation, prior-tree
    # accumulation) instead of inferring it from code. Remove after the audit.
    if get_setting("LATS_LOG_EXPAND_PROMPT", False):
        try:
            _nid = node.id if node is not None else "ROOT"
            logger.info("[LATS_EXPAND_PROMPT] node=%s allowed=%d branching=%d\n"
                        "===SYSTEM===\n%s\n===USER===\n%s\n[/LATS_EXPAND_PROMPT]",
                        _nid, len(allowed or []), branching,
                        messages[0].get("content", ""), messages[1].get("content", ""))
        except Exception:
            pass
    from agent_in_the_loop.purpose import llm_purpose
    try:
        with llm_purpose("lats_expand", node_id=node.id if node is not None else "ROOT"):
            resp = await retry_llm_call(llm, messages, label="lats_expand")
    except Exception as exc:
        logger.warning("[lats_expand] LLM call failed: %s", exc)
        return []
    # Account for LATS's own LLM spend so the per-turn/cumulative token counters
    # (and the UI) reflect it — otherwise a LATS-active turn silently undercounts.
    _usage = getattr(resp, "usage_metadata", None) or {}
    if _usage:
        _acc = state.get("_lats_expand_tokens") or {"in": 0, "out": 0}
        _acc["in"] += int(_usage.get("input_tokens", 0) or 0)
        _acc["out"] += int(_usage.get("output_tokens", 0) or 0)
        state["_lats_expand_tokens"] = _acc
    content = getattr(resp, "content", resp)
    if isinstance(content, list):     # some providers return content blocks
        content = " ".join(str(b.get("text", b)) if isinstance(b, dict) else str(b)
                           for b in content)
    # HARD dedup keys = this tree's probes (within-tree) UNION the run-level
    # ledger of every prior tree's executed probes (cross-tree, §3). So expand
    # drops a byte-identical re-run whether the original was in THIS tree or an
    # earlier one this run.
    _tree_keys = _existing_probe_keys(tree) if tree is not None else set()
    _ledger_keys = set(state.get("_lats_probe_ledger") or ())
    return _parse_expand_response(str(content or ""), allowed, branching,
                                  existing_keys=_tree_keys | _ledger_keys)


# =============================================================================
# COMPLETION / ARCHIVE (§5.4)
# =============================================================================

def _best_terminal(tree: ExploitTree) -> Optional[str]:
    terminals = [n for n in tree.nodes.values() if n.status == "terminal"]
    if not terminals:
        return None
    return max(terminals, key=lambda n: (n.value, n.depth)).id


def best_trajectory(tree: ExploitTree) -> List[str]:
    """Root-to-hot-leaf id path: follow best terminal if any, else highest-value
    live leaf."""
    target = tree.best_terminal_id or _best_terminal(tree)
    if target is None:
        leaves = _open_leaves(tree)
        if not leaves:
            return [tree.root_id]
        target = max(leaves, key=lambda n: n.value).id
    path = []
    nid: Optional[str] = target
    while nid is not None:
        path.append(nid)
        nid = tree.nodes[nid].parent_id
    return list(reversed(path))


def _archive_tree(state: dict, tree: ExploitTree, reason: str) -> None:
    """Drop the live tree (kept for the report via findings/graph) and clear
    _exploit_tree so a fresh search can start via lats_active next turn. Stamps
    the archive iteration so lats_active can enforce a re-activation cooldown
    (Fix B2) — a freshly collapsed tree must not immediately rebuild itself."""
    logger.info("[lats] archiving tree %s (%s): rollouts=%d nodes=%d",
                tree.root_id, reason, tree.rollouts, len(tree.nodes))
    state["_exploit_tree"] = None
    state["_lats_last_archive_iter"] = int(state.get("current_iteration", 0) or 0)


# =============================================================================
# CARRY-FORWARD (Fix A) — render the finished tree into execution_trace, the
# ONLY channel the next think node reads, so the agent inherits WHAT THE SEARCH
# LEARNED (structure + scores + best line + pruning reflections) instead of
# re-deriving it from raw probe logs. See internal/LATS_integration.md §handoff.
# =============================================================================

def _node_label(n: ExploitTreeNode) -> str:
    """Compact 'tool {args}' label for a probe node."""
    base = n.tool_name or (n.probe_rationale[:40] if n.probe_rationale else n.id)
    if n.tool_args:
        return f"{base} {str(n.tool_args)[:80]}"
    return base


def _trajectory_labels(tree: ExploitTree) -> List[str]:
    """best_trajectory() as readable probe labels (root excluded)."""
    labels: List[str] = []
    for nid in best_trajectory(tree):
        n = tree.nodes.get(nid)
        if n is None or n.parent_id is None:
            continue
        labels.append(n.tool_name or (n.probe_rationale[:30] if n.probe_rationale else nid))
    return labels


def _render_tree_summary(tree: ExploitTree, outcome: str) -> str:
    """Human/LLM-readable indented tree: every probe with its status, value,
    visit count, success star, danger flag, and pruning reflection. Capped at
    LATS_SUMMARY_MAX_NODES highest-value nodes so the block stays bounded."""
    depth_max = max((n.depth for n in tree.nodes.values()), default=0)
    lines = [
        f"LATS exploit-path search: {outcome} | rollouts={tree.rollouts} "
        f"nodes={len(tree.nodes)} maxdepth={depth_max}",
        f"Objective: {(tree.objective or 'n/a')[:200]}",
    ]
    traj = _trajectory_labels(tree)
    if traj:
        lines.append(f"Best line: {' -> '.join(traj)}")
    lines.append("Tree (probe [status] value=v visits=n | note):")
    cap = int(get_setting("LATS_SUMMARY_MAX_NODES", 40))
    count = [0]
    seen: set = set()

    def emit(nid: str, depth: int) -> None:
        if count[0] >= cap or nid in seen:   # cap + cycle/shared-child guard
            return
        n = tree.nodes.get(nid)
        if n is None:
            return
        seen.add(nid)
        count[0] += 1
        indent = "  " + "  " * depth
        if n.parent_id is None:
            lines.append(f"{indent}root [{(tree.objective or 'root')[:40]}]")
        else:
            note = (n.reflection or n.observation_summary or "").strip().replace("\n", " ")
            note = (" — " + note[:120]) if note else ""
            star = " *SUCCESS*" if n.exploit_succeeded else ""
            dang = " (dangerous)" if _is_dangerous(n) else ""
            lines.append(
                f"{indent}{_node_label(n)} [{n.status}] v={n.value:.2f} "
                f"n={n.visits}{star}{dang}{note}"
            )
        for c in sorted(
            (tree.nodes[c] for c in n.children if c in tree.nodes),
            key=lambda k: (-k.value, -k.visits),
        ):
            emit(c.id, depth + 1)

    emit(tree.root_id, 0)
    if len(tree.nodes) > count[0]:
        lines.append(f"  ... ({len(tree.nodes) - count[0]} more nodes truncated)")
    return "\n".join(lines)


def _carry_directive(tree: ExploitTree, outcome: str) -> str:
    """The un-wrapped 'Analysis:' line telling the agent how to ACT on the tree
    (the tree text itself is data, wrapped as untrusted output)."""
    if outcome == "terminal_success":
        return (
            "LATS confirmed an exploit path (see best line above). Continue along "
            "that line and convert it into the objective (submit/confirm). Do NOT "
            "restart discovery from scratch."
        )
    best = " -> ".join(_trajectory_labels(tree)) or "n/a"
    return (
        f"LATS explored the branches below and could not confirm the objective "
        f"this search. Highest-value line: {best}. Build on that line or the "
        f"highest-value open leaf. Do NOT re-run probes marked [pruned]/[failed] "
        f"with the same arguments — their notes say why they failed. If every "
        f"branch is pruned, pivot to an attack axis not present in the tree."
    )


def _carry_tree_forward(state: dict, tree: ExploitTree, outcome: str) -> None:
    """Fix A: append a rendered tree-summary step to execution_trace so the next
    think node inherits the search's structure, scores, and lessons. No-op for a
    tree that never branched (nothing worth carrying)."""
    if len(tree.nodes) <= 1:
        return
    step = {
        "iteration": int(state.get("current_iteration", 0) or 0),
        "phase": state.get("current_phase", "exploitation") or "exploitation",
        "thought": f"[LATS] exploit-path tree search ended ({outcome}).",
        "reasoning": "LATS search summary carried into agent context (Fix A).",
        "tool_name": "lats_search",
        "tool_args": {"objective": (tree.objective or "")[:200]},
        "tool_output": _render_tree_summary(tree, outcome),
        "success": any(n.exploit_succeeded for n in tree.nodes.values()),
        "output_analysis": _carry_directive(tree, outcome),
        "step_id": f"lats-summary-{tree.root_id}",
    }
    base = state.get("execution_trace", []) or []
    state["execution_trace"] = base + [step]
    # Also record a compact, persistent digest so ALL prior trees accumulate for
    # the next tree independently of execution_trace's eviction window.
    _append_tree_digest(state, tree, outcome)


async def _finish_search(state: dict, tree: ExploitTree, outcome: str, *,
                         shadow: bool, streaming_callbacks: Any,
                         session_id: Optional[str], archive: bool) -> None:
    """Single closing path for a search: persist the final scored snapshot,
    stream the closing tree_update + complete, carry the tree forward into agent
    context (drive mode only), and archive when handing back to legacy."""
    state["_exploit_tree"] = tree.model_dump()
    await _emit(streaming_callbacks, session_id, "on_lats_tree_update",
                _search_id(session_id, tree), _tree_view(state, tree, shadow))
    await _emit(streaming_callbacks, session_id, "on_lats_complete",
                _search_id(session_id, tree), best_trajectory(tree),
                outcome, _complete_metrics(tree))
    if not shadow:
        _carry_tree_forward(state, tree, outcome)
    if archive:
        _archive_tree(state, tree, outcome)


def _complete(decision: Any, tree: ExploitTree, reason: str) -> Any:
    """Return a decision forced to action=complete with the best trajectory.
    Duck-typed on `.model_copy` so tests can pass a lightweight stand-in."""
    traj = best_trajectory(tree)
    thought = f"[LATS] {reason}: {' -> '.join(traj)}"
    completion_reason = f"LATS {reason}"
    if hasattr(decision, "model_copy"):
        return decision.model_copy(update={"action": "complete", "thought": thought,
                                           "completion_reason": completion_reason})
    # dict fallback (tests)
    if isinstance(decision, dict):
        d = dict(decision)
        d["action"] = "complete"
        d["thought"] = thought
        d["completion_reason"] = completion_reason
        return d
    return decision


# =============================================================================
# EXECUTED-STEP GATHERING + ATTRIBUTION (§20.2)
# =============================================================================

def _executed_steps(state: dict) -> List[dict]:
    """The step(s) whose output is pending this turn: a plan_tools wave (each
    step stamped with its wave index) or a single use_tool step."""
    plan = state.get("_current_plan")
    if plan and plan.get("steps"):
        out = []
        for i, s in enumerate(plan["steps"]):
            s2 = dict(s)
            s2["_step_index"] = i
            out.append(s2)
        return out
    single = state.get("_current_step")
    if single:
        s2 = dict(single)
        s2.setdefault("_step_index", 0)
        return [s2]
    return []


def _ordered_executing_children(tree: ExploitTree) -> List[ExploitTreeNode]:
    """Executing children in stable wave order (parent insertion order, then
    each parent's children order), so positional attribution to _current_plan
    steps is deterministic (§20.2)."""
    out = []
    for node in list(tree.nodes.values()):
        for cid in node.children:
            c = tree.nodes.get(cid)
            if c is not None and c.status == "executing":
                out.append(c)
    return out


def _step_ran(step: dict) -> bool:
    """A step produced a real result (ran), vs never left the harness."""
    return (step.get("tool_output") is not None
            or step.get("success") is not None
            or bool(step.get("error_message")))


def _match_children_to_steps(children, steps):
    """Pair each executing child with an executed step by tool_name (consuming
    each step once, in order). Returns [(child, step_or_None)]. Matching by
    tool_name (not blind position) is robust to a child stranded from a prior
    wave and to shadow mode, where the legacy step's tool_name differs (§20.2).
    """
    ran = [s for s in steps if _step_ran(s)]
    used = [False] * len(ran)
    pairs = []
    for child in children:
        match = None
        for j, s in enumerate(ran):
            if not used[j] and s.get("tool_name") == child.tool_name:
                used[j] = True
                match = s
                break
        pairs.append((child, match))
    return pairs


def _evaluate_wave(tree: ExploitTree, state: dict, analysis: Any) -> bool:
    """Evaluate + backprop the children we issued last turn, but ONLY those that
    ACTUALLY EXECUTED (§20.2). Returns True if at least one child produced a
    result (so the caller counts a rollout). Mutates the tree in place.

    Children that never ran this turn (no matching executed step) are reset to
    'proposed' so the search re-selects them (e.g. a metasploit probe re-routed
    to ask_user, §20.4) — leaving them 'executing' would strand them forever and
    skew later attribution.
    """
    children = _ordered_executing_children(tree)
    if not children:
        return False

    # Operator rejected the pending confirmation: prune, do NOT evaluate or
    # count a rollout (a rejection is not a probe result).
    if state.get("_reject_tool"):
        for child in children:
            child.status = "pruned"
            child.reflection = "operator declined"
        return False

    steps = _executed_steps(state)
    pairs = _match_children_to_steps(children, steps)
    executed = [(c, s) for c, s in pairs if s is not None]

    # Reset the never-ran children so they are re-selectable next turn.
    for child, step in pairs:
        if step is None:
            child.status = "proposed"

    if not executed:
        return False

    phase = state.get("current_phase")
    before, after = _post_expl_snapshots(state)
    prune_floor = get_setting("LATS_PRUNE_FLOOR", 0.15)

    # Which child, if any, is credited with the AGGREGATE wave-level signal
    # (exploit_succeeded / finding confidence). per_step localizes it; otherwise
    # credit the single strongest-signal child so we never mark every sibling
    # terminal (Bug: over-credit). A single executed step is always credited.
    credited_child = _credited_child(executed, analysis)

    for child, step in executed:
        credited = child is credited_child
        child.local_value = lats_value(step, analysis, phase=phase, before=before,
                                       after=after, credited=credited)
        # cap=600 so the inspector's OBSERVATION section shows a useful slice
        # (outline rows ellipsis-clamp it; prompt rendering re-slices to [:80]).
        child.observation_summary = _summarize(step.get("tool_output"), cap=600)
        child.verdict = _verdict_for(step, analysis)
        child.error_class = step.get("error_class", "") or ""
        # W4: stamp the LLM-emitted response_class (always classified).
        rc = _response_class_for(step, analysis)
        child.response_class = rc
        child.duration_ms = int(step.get("duration_ms", 0) or 0)
        child.step_id = step.get("step_id")
        child.finding_confidence_delta = _new_finding_confidence(step, analysis, credited)
        child.exploit_succeeded = _exploit_succeeded(step, analysis, credited)
        child.status = "terminal" if child.exploit_succeeded else "evaluated"
        lats_backprop(tree, child.id, child.local_value)
        # W4: when a class is recognized, its actionable reflection carries the MOVE
        # to the next expand / cross-tree digest (kept or pruned). The class score
        # already decides prune vs keep (bypassable classes sit above the floor, dead
        # ones below), so NO prune-exemption special-case is needed.
        if rc in _RC_REFLECTIONS:
            child.reflection = _RC_REFLECTIONS[rc]
        if not child.exploit_succeeded and child.local_value < prune_floor:
            child.status = "pruned"
            if not child.reflection:            # legacy fallback when no class
                child.reflection = _reflect(step, analysis)
    return True


def _credited_child(executed, analysis):
    """The single child credited with the aggregate wave signal. If any child
    already localizes the signal via per_step, no aggregate credit is given
    (return None). A single executed step is credited. Otherwise pick the
    strongest-signal child by its non-credited base value."""
    if len(executed) == 1:
        return executed[0][0]
    per_step = _attr(analysis, "per_step", []) or []
    if per_step:
        return None                     # per_step localizes; no blanket credit
    # No per-step attribution: credit the strongest child so exactly one can win.
    # Rank on the LEGACY value (never the W4 response-class value): a kept-alive
    # input_filter's +0.20 boost is "worth continuing", NOT evidence it caused the
    # foothold, so it must not outrank a genuinely-informative sibling for credit.
    def _base(cs):
        c, s = cs
        return _legacy_web_value(s, analysis, credited=False)
    return max(executed, key=_base)[0]


def _post_expl_snapshots(state: dict):
    """Cheap before/after engagement-state snapshots for post-exploitation
    scoring (§6.1). In v1 we compare the tree-persisted 'before' against the
    current state; when unavailable both are empty and the web value function
    is used anyway (phase != post_exploitation)."""
    ti = state.get("target_info", {}) or {}
    snap = {
        "sessions": ti.get("sessions", []),
        "credentials": ti.get("credentials", []),
        "hosts": ti.get("hosts", []) or ti.get("services", []),
    }
    # For v1 we do not diff across the fold; both snapshots equal, so the delta
    # helpers return 0 and post-expl value leans on the finding signal. Refined later.
    return snap, snap


def _as_wave_or_use_tool(decision: Any, wave: List[ExploitTreeNode]) -> Any:
    """Override the decision's action with the next LATS move: a plan_tools wave
    when >= 2 probes, else a single use_tool. Dangerous steps are allowed; the
    existing confirmation gate handles the prompt (§20.3).

    CRITICAL: for a real LLMDecision, `tool_plan` MUST be a ToolPlan model, not a
    dict — pydantic's model_copy does NOT coerce update values, and think_node
    calls `decision.tool_plan.model_dump()`. A dict there crashes the run.
    """
    is_wave = len(wave) >= 2
    if not is_wave and not wave:
        return decision   # nothing to issue; leave the decision alone

    if hasattr(decision, "model_copy"):
        if is_wave:
            from state import ToolPlan, ToolPlanStep
            plan = ToolPlan(steps=[
                ToolPlanStep(tool_name=k.tool_name, tool_args=k.tool_args or {},
                             rationale=k.probe_rationale)
                for k in wave
            ], plan_rationale="[LATS] wave")
            return decision.model_copy(update={"action": "plan_tools", "tool_plan": plan,
                                               "tool_name": None, "tool_args": None})
        best = wave[0]
        return decision.model_copy(update={"action": "use_tool",
                                           "tool_name": best.tool_name,
                                           "tool_args": best.tool_args or {},
                                           "tool_plan": None})
    # dict fallback (unit tests): keep the plain-dict shape for assertions.
    d = dict(decision)
    if is_wave:
        d["action"] = "plan_tools"
        d["tool_plan"] = _wave(wave)
    else:
        best = wave[0]
        d["action"] = "use_tool"
        d["tool_name"] = best.tool_name
        d["tool_args"] = best.tool_args or {}
    return d


# =============================================================================
# STREAMING (§17.4) — emit on_lats_* to the per-session StreamingCallback so the
# UI card mutates in place. Resilient: no-op when there is no callback (tests).
# =============================================================================

def _search_id(session_id: Optional[str], tree: ExploitTree) -> str:
    """Unique per session per search (§20.12). A tree created after a reset gets
    a new root_id, so a second search renders as a distinct card."""
    return f"{session_id or 'sess'}:{tree.root_id}"


def _tree_view(state: dict, tree: ExploitTree, shadow: bool) -> dict:
    return tree.to_view(
        search_id=_search_id(state.get("session_id"), tree),
        phase=state.get("current_phase", "") or "",
        shadow_mode=shadow,
        max_rollouts=int(get_setting("LATS_MAX_ROLLOUTS", 24)),
        max_depth=int(get_setting("LATS_MAX_DEPTH", 6)),
        best_trajectory=best_trajectory(tree),
    )


def _complete_metrics(tree: ExploitTree) -> dict:
    """A/B telemetry for on_lats_complete (§20.13)."""
    pruned = sum(1 for n in tree.nodes.values() if n.status == "pruned")
    max_depth = max((n.depth for n in tree.nodes.values()), default=0)
    return {
        "rollouts": tree.rollouts,
        "max_depth_reached": max_depth,
        "nodes_total": len(tree.nodes),
        "pruned_count": pruned,
        "outcome_terminal": tree.best_terminal_id is not None,
    }


async def _emit(streaming_callbacks: Any, session_id: Optional[str], method: str, *args) -> None:
    if not streaming_callbacks:
        return
    getter = getattr(streaming_callbacks, "get", None)
    cb = getter(session_id) if getter else None
    if cb is None:
        return
    fn = getattr(cb, method, None)
    if fn is None:
        return
    try:
        await fn(*args)
    except Exception as exc:   # streaming must never break the search
        logger.warning("[lats] stream %s failed: %s", method, exc)


# =============================================================================
# THE HOOK (§5.3) — runs inside think_node AFTER the think LLM call. Uses
# decision.output_analysis as the evaluation signal and (in DRIVE mode) overrides
# the action with the next LATS move. Strict no-op when LATS_ENABLED=false or
# when LATS is not driving. `llm` is the SAME single agent model think_node uses.
# =============================================================================

async def lats_hook(state: dict, decision: Any, *, llm: Any,
                    streaming_callbacks: Any = None, session_id: Optional[str] = None) -> Any:
    if not get_setting("LATS_ENABLED", False):
        return decision
    shadow = bool(get_setting("LATS_SHADOW_MODE", False))

    # ---- ENTER (no tree) or STAY (tree live) ----
    tree_dict = state.get("_exploit_tree")
    newly_created = False
    if not tree_dict:
        if not lats_active(state):
            return decision                              # legacy path, untouched
        probes = await lats_expand(llm, state, None)     # LATS's own assessment
        if len(probes) < int(get_setting("LATS_MIN_HYPOTHESES", 2)):
            return decision                              # < 2 credible probes: no real branch
        tree = _new_tree(state, probes)
        newly_created = True
    else:
        tree = ExploitTree(**tree_dict)
        if _lats_should_reset(state, tree):
            await _finish_search(state, tree, "reset", shadow=shadow,
                                 streaming_callbacks=streaming_callbacks,
                                 session_id=session_id, archive=True)
            return decision                              # archived; fresh tree may start next turn

    if newly_created:
        logger.info(
            "[lats][MODE] search created: LATS_ENABLED=%s LATS_SHADOW_MODE=%s -> %s "
            "(session=%s)",
            get_setting("LATS_ENABLED"), shadow,
            "OBSERVE-ONLY (agent drives)" if shadow else "DRIVE (LATS issues probes)",
            session_id,
        )
        await _emit(streaming_callbacks, session_id, "on_lats_start",
                    _search_id(session_id, tree), tree.objective,
                    state.get("current_phase", "") or "",
                    {"max_rollouts": int(get_setting("LATS_MAX_ROLLOUTS", 24)),
                     "max_depth": int(get_setting("LATS_MAX_DEPTH", 6))},
                    shadow)

    analysis = _attr(decision, "output_analysis")

    # ---- 1. EVALUATE + BACKPROP the wave we issued last turn ----
    if _evaluate_wave(tree, state, analysis):
        tree.rollouts += 1

    # ---- 2. EXITS (order: success -> collapse[hand back] -> exhausted[hand back]
    #      -> budget[complete]). Only a claimed foothold or a spent budget END
    #      the run; running out of tree to search hands the objective back to
    #      legacy ReAct with the carried-forward summary, so the agent keeps
    #      working instead of the whole run completing on an empty search. ----
    override = None
    outcome = None
    if any(n.status == "terminal" for n in tree.nodes.values()):
        tree.best_terminal_id = _best_terminal(tree)
        override, outcome = "lats_terminal_success", "terminal_success"
    elif _single_open_line(tree):
        # One credible line left, nothing to branch on: stream the FINAL scored
        # tree, carry it forward, and hand the obvious line back to legacy.
        await _finish_search(state, tree, "branch_collapsed", shadow=shadow,
                             streaming_callbacks=streaming_callbacks,
                             session_id=session_id, archive=True)
        return decision                                  # legacy drives the one obvious line
    elif _tree_exhausted(tree):
        # Every branch explored, no foothold: hand back to legacy (Fix B1).
        await _finish_search(state, tree, "exhausted", shadow=shadow,
                             streaming_callbacks=streaming_callbacks,
                             session_id=session_id, archive=True)
        return decision
    elif _budget_hit(tree):
        override, outcome = "lats_budget_exhausted", "budget_exhausted"

    # ---- 3. SELECT + 4. EXPAND (skip when exiting via complete) ----
    wave: List[ExploitTreeNode] = []
    if override is None:
        node = tree.nodes[lats_select(tree, get_setting("LATS_UCT_C", 1.4))]
        tree.active_node_id = node.id
        if _can_expand(node) and not _has_proposed_children(tree, node):
            max_nodes = int(get_setting("LATS_MAX_TREE_NODES", 60))
            for cand in await lats_expand(llm, state, node, tree=tree):
                if len(tree.nodes) >= max_nodes:
                    break
                _add_child(tree, node, cand)
        kids = _proposed_children(tree, node)
        wave = _mutex_safe_subset(kids)
        for k in wave:
            k.status = "executing"

        # ---- STALL GUARD (Fix B1). lats_select descends greedily by UCT down a
        # SINGLE path, so it can land on a dead frontier (a depth-capped leaf, or
        # one whose expand produced nothing) while expandable/queued branches
        # remain on OTHER paths. Archiving here would abandon those branches
        # prematurely; instead PRUNE the dead frontier so the descent reaches the
        # other branches next turn. This guarantees forward progress — one node
        # pruned per otherwise-stuck turn — so the tree always converges to a real
        # top-level exit (collapse / exhausted) rather than becoming a "zombie"
        # that stays live forever driving nothing. Only close out here as a
        # safety net when we cannot even prune and nothing is pending.
        if not wave:
            pruned = False
            if (node.parent_id is not None and node.status != "pruned"
                    and not _live_children(tree, node)):
                node.status = "pruned"
                if not node.reflection:
                    node.reflection = "pruned: no issuable move (depth cap or expand produced nothing)"
                pruned = True
            if not pruned and not _executing_children(tree):
                await _finish_search(state, tree, "exhausted", shadow=shadow,
                                     streaming_callbacks=streaming_callbacks,
                                     session_id=session_id, archive=True)
                return decision

    # ---- budget: run-ending exit (carry forward, keep tree, complete) ----
    if override is not None:
        await _finish_search(state, tree, outcome, shadow=shadow,
                             streaming_callbacks=streaming_callbacks,
                             session_id=session_id, archive=False)
        if shadow:
            return decision
        return _complete(decision, tree, override)

    # ---- normal turn: persist + stream the snapshot (once per wave) ----
    state["_exploit_tree"] = tree.model_dump()
    await _emit(streaming_callbacks, session_id, "on_lats_tree_update",
                _search_id(session_id, tree), _tree_view(state, tree, shadow))

    # ---- SHADOW: build/stream the tree but never drive ----
    if shadow:
        return decision

    # ---- DRIVE (Step 6): issue the next wave ----
    return _as_wave_or_use_tool(decision, wave)
