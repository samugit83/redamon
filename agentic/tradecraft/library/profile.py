"""What Library now searches for: the agent's current goal and the session's structured facts
(owner decision 2026-11-17, which replaced T8.1's fixed checkpoints).

The goal is the step the think node holds as the one at hand: the first todo item in progress,
else the first pending one, else the current objective (the person's message). The model or the
person wrote it, and target text the model read can colour it: the owner accepted that when it
chose this design (the R-420 card correction). Before it is searched (``query_of``), URLs,
addresses and bare numbers go: they name the target, never a technique.

The facts are structured: the skill's topic (a built-in skill is a vocabulary topic) and its
label, the phase, the target's technologies as vocabulary ids, the CVE ids a finding confirmed
(the newest ``MAX_CVES``: a scan listing hundreds would otherwise fix the set), the finding types
of the agent's fixed list, and whether the last target tool ran or failed. A CVE id that recon or
a scan only listed is no fact: it would fill the block with pages off the agent's goal. A tool
result adds its success flag only: its text never becomes a query.

``target_info`` and the findings are written from the model's reading of tool output, so they
are target-influenced too: a technology is kept only when the vocabulary knows it, a CVE id only
when the pattern matches, a finding type only when it is on the list.

The focus of the last check rides in the run's hint log (the ``library_now`` entry), so a resume
that runs the think node again on the saved state finds nothing new.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Iterable, Mapping, Optional

from tradecraft.ingest import entities as entity_rules
from tradecraft.vocab import load_vocab

MAX_TECHS = 30
MAX_CVES = 50
MAX_RESULTS = 50
GOAL_CHARS = 300
SKILL_CHARS = 120

# Tools whose output is the library or the web, never the target's.
NOT_TARGET = frozenset({"tradecraft_lookup", "tradecraft_search", "tradecraft_ask", "web_search", "google_dork"})
# Tools that read stored data rather than try something against the target: their success says
# nothing about how the last attempt went.
NOT_AN_ATTEMPT = NOT_TARGET | {"query_graph", "graph_schema", "graph_summary"}
# The finding types of the think prompt's output contract (``prompts/base.py``, "finding_type");
# "custom" says nothing about where the attack stands.
FINDING_TYPES = frozenset({
    "vulnerability_confirmed", "credential_found", "exploit_success", "access_gained", "privilege_escalation",
    "service_identified", "exploit_module_found", "defense_detected", "configuration_found",
    "information_disclosure", "data_exfiltration", "lateral_movement", "persistence_established",
    "denial_of_service_success", "social_engineering_success", "remote_code_execution", "session_hijacked",
})
# The finding types that say a vulnerability is real: the CVE ids such a finding names are searched.
CONFIRMING = FINDING_TYPES - {"service_identified", "configuration_found", "exploit_module_found",
                              "defense_detected", "information_disclosure"}
OUTCOMES = ("", "ok", "failed")

# Characters that hide or reorder text: controls other than whitespace (C0 and C1), bidi
# controls and zero-width characters. Postgres also refuses a NUL in a text parameter.
HIDDEN = re.compile("[\x00-\x08\x0e-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_URL = re.compile(r"\b[a-z][a-z0-9+.\-]*://\S*", re.IGNORECASE)
_EMAIL = re.compile(r"\S+@\S+")
_IPV4 = re.compile(r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5}|/\d{1,2})?(?![0-9])")
_NUMBER = re.compile(r"(?<![a-z0-9])\d+(?:[.,:/]\d+)*(?![a-z0-9])", re.IGNORECASE)


@dataclass(frozen=True)
class Focus:
    goal: str = ""
    topic: Optional[str] = None
    skill: str = ""
    phase: str = ""
    technologies: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()
    findings: tuple[str, ...] = ()
    outcome: str = ""
    # The tool results already read for CVE ids and the outcome: a resume reads them once.
    results: tuple[str, ...] = ()

    def to_log(self) -> dict[str, Any]:
        return {"goal": self.goal, "topic": self.topic, "skill": self.skill, "phase": self.phase,
                "technologies": list(self.technologies), "cves": list(self.cves), "findings": list(self.findings),
                "outcome": self.outcome, "results": list(self.results)}

    @classmethod
    def from_log(cls, entry: Optional[Mapping[str, Any]]) -> Optional["Focus"]:
        """The focus a run saved, or None. The saved state is read like any input: only the
        expected types, within the caps."""
        if not isinstance(entry, Mapping):
            return None
        topic, outcome = entry.get("topic"), entry.get("outcome")
        return cls(goal=one_line(entry.get("goal"))[:GOAL_CHARS],
                   topic=topic if isinstance(topic, str) and topic in load_vocab().topic_ids else None,
                   skill=one_line(entry.get("skill"))[:SKILL_CHARS],
                   phase=one_line(entry.get("phase"))[:40],
                   technologies=_strings(entry.get("technologies"), MAX_TECHS),
                   cves=tuple(c for c in _strings(entry.get("cves"), MAX_CVES) if entity_rules.cve_ids(c) == [c]),
                   findings=tuple(f for f in _strings(entry.get("findings"), len(FINDING_TYPES)) if f in FINDING_TYPES),
                   outcome=outcome if outcome in OUTCOMES else "",
                   results=_strings(entry.get("results"), MAX_RESULTS))


def one_line(value: Any) -> str:
    """The text on one line, with no hidden character."""
    return " ".join(HIDDEN.sub("", value).split()) if isinstance(value, str) else ""


def _strings(value: Any, cap: int) -> tuple[str, ...]:
    out: list[str] = []
    for item in value if isinstance(value, (list, tuple)) else ():
        if isinstance(item, str) and item and item[:200] not in out:
            out.append(item[:200])
    return tuple(out[:cap])


def _get(obj: Any, key: str) -> Any:
    return obj.get(key) if isinstance(obj, Mapping) else getattr(obj, key, None)


def _newest(items: Iterable[str], cap: int) -> tuple[str, ...]:
    """The last ``cap`` distinct items, each where it was seen last: an id named again is newest."""
    out: list[str] = []
    for item in items:
        if item in out:
            out.remove(item)
        out.append(item)
    return tuple(out[-cap:])


def _union(first: Iterable[str], then: Iterable[str], cap: int) -> tuple[str, ...]:
    out: list[str] = []
    for item in [*first, *then]:
        if item not in out:
            out.append(item)
    return tuple(out[:cap])


def topic_of(state: Mapping[str, Any]) -> Optional[str]:
    path = str(state.get("attack_path_type") or "")
    return path if path in load_vocab().topic_ids else None


def objective_of(state: Mapping[str, Any]) -> str:
    objectives = state.get("conversation_objectives") or []
    index = state.get("current_objective_index")
    if isinstance(index, int) and 0 <= index < len(objectives) and isinstance(objectives[index], Mapping):
        return str(objectives[index].get("content") or "")
    return str(state.get("original_objective") or "")


def goal_of(state: Mapping[str, Any]) -> str:
    """The step at hand: the first todo item in progress, else the first pending one, else the
    current objective. One line, at most ``GOAL_CHARS``."""
    todos = [t for t in state.get("todo_list") or [] if isinstance(t, Mapping)]
    for status in ("in_progress", "pending"):
        for item in todos:
            text = one_line(item.get("description")) if item.get("status") == status else ""
            if text:
                return text[:GOAL_CHARS]
    return one_line(objective_of(state))[:GOAL_CHARS]


def query_of(goal: str) -> str:
    """The goal as a search query: its words, without the URLs, addresses and bare numbers that
    name the target; the CVE ids it names are kept whole, so search matches them exactly."""
    cves = entity_rules.cve_ids(goal)
    text = goal
    for cve in cves:
        text = re.sub(re.escape(cve), " ", text, flags=re.IGNORECASE)
    for pattern in (_URL, _EMAIL, _IPV4, _NUMBER):
        text = pattern.sub(" ", text)
    return " ".join([*text.split(), *cves])


def new_results(state: Mapping[str, Any]) -> list[tuple[str, str, str, bool]]:
    """(id, tool, output, ran) of the tool results the think node is about to read: the single
    step's and the plan wave's, before their analysis."""
    out: list[tuple[str, str, str, bool]] = []
    step = state.get("_current_step")
    if isinstance(step, Mapping) and step.get("tool_output") is not None and not step.get("output_analysis"):
        ident = str(step.get("step_id") or f"step:{state.get('current_iteration', 0)}")
        out.append((ident, str(step.get("tool_name") or ""), str(step.get("tool_output") or ""),
                    step.get("success") is not False))
    plan = state.get("_current_plan")
    if isinstance(plan, Mapping) and not plan.get("_analyzed"):
        wave = str(plan.get("wave_id") or f"plan:{state.get('current_iteration', 0)}")
        for n, item in enumerate(plan.get("steps") or []):
            if isinstance(item, Mapping) and item.get("tool_output") is not None:
                out.append((f"{wave}:{n}", str(item.get("tool_name") or ""), str(item.get("tool_output") or ""),
                            item.get("success") is not False))
    return out[:MAX_RESULTS]


def _is_attempt(tool: str) -> bool:
    return bool(tool) and tool not in NOT_AN_ATTEMPT and not tool.startswith(("fs_", "job_"))


def build(state: Mapping[str, Any], previous: Optional[Focus]) -> Focus:
    """The focus now: what the run knows, with what the previous check had already seen."""
    from tradecraft.library.search import technologies_of

    target = state.get("target_info") or {}
    techs = technologies_of(_get(target, "technologies") or [])
    cves: list[str] = []
    findings: list[str] = []
    # The findings are the session's whole memory, oldest first: read again at every think.
    for finding in state.get("chain_findings_memory") or []:
        if not isinstance(finding, Mapping):
            continue
        if finding.get("finding_type") in FINDING_TYPES:
            findings.append(finding["finding_type"])
        if finding.get("finding_type") in CONFIRMING:
            for value in finding.get("related_cves") or []:
                if isinstance(value, str):
                    cves += entity_rules.cve_ids(value)
    checked = set(previous.results) if previous else set()
    results = new_results(state)
    attempts = [ran for ident, tool, _output, ran in results if ident not in checked and _is_attempt(tool)]
    outcome = ("ok" if all(attempts) else "failed") if attempts else (previous.outcome if previous else "")
    return Focus(
        goal=goal_of(state),
        topic=topic_of(state),
        skill=one_line(str(state.get("attack_path_type") or ""))[:SKILL_CHARS],
        phase=str(state.get("current_phase") or "informational"),
        technologies=_union(previous.technologies if previous else (), techs, MAX_TECHS),
        cves=_newest(cves, MAX_CVES),
        findings=tuple(sorted(set(previous.findings if previous else ()) | set(findings))),
        outcome=outcome,
        results=tuple(ident for ident, _t, _o, _r in results) or (previous.results if previous else ()),
    )


def changes(previous: Optional[Focus], current: Focus) -> tuple[str, ...]:
    """What changed since the last check: ``start`` for a run's first, then the goal, the skill,
    the phase, a new technology, CVE id or finding type, the last attempt's outcome."""
    if previous is None:
        return ("start",)
    fired = []
    if current.goal.lower() != previous.goal.lower():
        fired.append("goal")
    if (current.topic, current.skill) != (previous.topic, previous.skill):
        fired.append("skill")
    if current.phase != previous.phase:
        fired.append("phase")
    if set(current.technologies) - set(previous.technologies):
        fired.append("technology")
    if set(current.cves) - set(previous.cves):
        fired.append("cve")
    if set(current.findings) - set(previous.findings):
        fired.append("finding")
    if current.outcome != previous.outcome:
        fired.append("outcome")
    return tuple(fired)
