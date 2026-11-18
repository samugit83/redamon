"""What Library now searches for: the steps at hand and the session's structured facts (owner
decision 2026-11-17, which replaced T8.1's fixed checkpoints).

The steps at hand (``steps_of``) are the ones the agent is about to take, not the one it just
took: the todo item in progress and the next pending one. Models mark a step in progress in the
same answer that takes its first action, so a step's pages must be there while it is still the
next one. The agent's recommended next steps are no step: in most answers the first one is the
action that same answer takes. With nothing listed yet, the objective (the person's message) is
the step. The model or the person wrote them, and target text the model read can colour them: the
owner accepted that when it chose this design (the R-420 card correction). Before a step is searched (``query_of``), URLs,
addresses and bare numbers go: they name the target, never a technique.

The facts are the structured inputs of a search: the skill's topic (a built-in skill is a
vocabulary topic) and its label, the phase, the target's technologies as vocabulary ids, and the
CVE ids a finding confirmed (the newest ``MAX_CVES``: a scan listing hundreds would otherwise fix
the set). A CVE id that recon or a scan only listed is no fact: it would fill the block with pages
off the agent's goal. Finding types and the last attempt's outcome are no search input (the same
search would find the same pages), so they never start one; a tool result's text never becomes a
query.

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
GOAL_CHARS = 300
# The CVE pass searches the newest confirmed ids only.
SEARCHED_CVES = 3
SKILL_CHARS = 120

# The finding types of the think prompt's output contract (``prompts/base.py``, "finding_type").
FINDING_TYPES = frozenset({
    "vulnerability_confirmed", "credential_found", "exploit_success", "access_gained", "privilege_escalation",
    "service_identified", "exploit_module_found", "defense_detected", "configuration_found",
    "information_disclosure", "data_exfiltration", "lateral_movement", "persistence_established",
    "denial_of_service_success", "social_engineering_success", "remote_code_execution", "session_hijacked",
})
# The finding types that say a vulnerability is real: the CVE ids such a finding names are searched.
CONFIRMING = FINDING_TYPES - {"service_identified", "configuration_found", "exploit_module_found",
                              "defense_detected", "information_disclosure"}

# Characters that hide or reorder text: controls other than whitespace (C0 and C1), bidi
# controls and zero-width characters. Postgres also refuses a NUL in a text parameter.
HIDDEN = re.compile("[\x00-\x08\x0e-\x1f\x7f-\x9f\u061c\u200b-\u200f\u202a-\u202e\u2060-\u2069\ufeff]")
_URL = re.compile(r"\b[a-z][a-z0-9+.\-]*://\S*", re.IGNORECASE)
_EMAIL = re.compile(r"\S+@\S+")
_IPV4 = re.compile(r"(?<![0-9.])\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5}|/\d{1,2})?(?![0-9])")
_NUMBER = re.compile(r"(?<![a-z0-9])\d+(?:[.,:/]\d+)*(?![a-z0-9])", re.IGNORECASE)


# A step's kind: in progress, the next one.
STEP_LABELS = ("now", "next")


@dataclass(frozen=True)
class Focus:
    steps: tuple[tuple[str, str], ...] = ()
    topic: Optional[str] = None
    skill: str = ""
    phase: str = ""
    technologies: tuple[str, ...] = ()
    cves: tuple[str, ...] = ()

    def to_log(self) -> dict[str, Any]:
        return {"steps": [list(s) for s in self.steps], "topic": self.topic, "skill": self.skill, "phase": self.phase,
                "technologies": list(self.technologies), "cves": list(self.cves)}

    @classmethod
    def from_log(cls, entry: Optional[Mapping[str, Any]]) -> Optional["Focus"]:
        """The focus a run saved, or None. The saved state is read like any input: only the
        expected types, within the caps."""
        if not isinstance(entry, Mapping):
            return None
        topic = entry.get("topic")
        steps = []
        for item in entry.get("steps") or []:
            if (isinstance(item, (list, tuple)) and len(item) == 2 and item[0] in STEP_LABELS
                    and one_line(item[1]) and len(steps) < len(STEP_LABELS)):
                steps.append((item[0], one_line(item[1])[:GOAL_CHARS]))
        return cls(steps=tuple(steps),
                   topic=topic if isinstance(topic, str) and topic in load_vocab().topic_ids else None,
                   skill=one_line(entry.get("skill"))[:SKILL_CHARS],
                   phase=one_line(entry.get("phase"))[:40],
                   technologies=_strings(entry.get("technologies"), MAX_TECHS),
                   cves=tuple(c for c in _strings(entry.get("cves"), MAX_CVES) if entity_rules.cve_ids(c) == [c]))


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


def _first_todo(todos: list[Mapping[str, Any]], status: str) -> str:
    return next((t for t in (one_line(i.get("description"))[:GOAL_CHARS] for i in todos if i.get("status") == status)
                 if t), "")


def steps_of(state: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    """The steps at hand, each one line of at most ``GOAL_CHARS``, none twice: (``now``, the todo
    item in progress), (``next``, the first pending one). With no todo item, the objective is
    ``now``."""
    todos = [t for t in state.get("todo_list") or [] if isinstance(t, Mapping)]
    current, following = _first_todo(todos, "in_progress"), _first_todo(todos, "pending")
    if not todos:
        candidates = (("now", one_line(objective_of(state))[:GOAL_CHARS]),)
    else:
        candidates = (("now", current), ("next", following))
    out: list[tuple[str, str]] = []
    for label, text in candidates:
        if text and text.lower() not in {t.lower() for _l, t in out}:
            out.append((label, text))
    if not out:
        objective = one_line(objective_of(state))[:GOAL_CHARS]
        out = [("now", objective)] if objective else []
    return tuple(out)


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


def build(state: Mapping[str, Any], previous: Optional[Focus]) -> Focus:
    """The focus now: what the run knows, with what the previous check had already seen."""
    from tradecraft.library.search import technologies_of

    target = state.get("target_info") or {}
    techs = technologies_of(_get(target, "technologies") or [])
    cves: list[str] = []
    # The findings are the session's whole memory, oldest first: read again at every think.
    for finding in state.get("chain_findings_memory") or []:
        if isinstance(finding, Mapping) and finding.get("finding_type") in CONFIRMING:
            for value in finding.get("related_cves") or []:
                if isinstance(value, str):
                    cves += entity_rules.cve_ids(value)
    return Focus(
        steps=steps_of(state),
        topic=topic_of(state),
        skill=one_line(str(state.get("attack_path_type") or ""))[:SKILL_CHARS],
        phase=str(state.get("current_phase") or "informational"),
        technologies=_union(previous.technologies if previous else (), techs, MAX_TECHS),
        cves=_newest(cves, MAX_CVES),
    )


def changes(previous: Optional[Focus], current: Focus) -> tuple[str, ...]:
    """What changed since the last check: ``start`` for a run's first, then a step (``goal``), the
    skill, the phase, a new technology, a newly confirmed CVE id."""
    if previous is None:
        return ("start",)
    fired = []
    if [t.lower() for _l, t in current.steps] != [t.lower() for _l, t in previous.steps]:
        fired.append("goal")
    if (current.topic, current.skill) != (previous.topic, previous.skill):
        fired.append("skill")
    if current.phase != previous.phase:
        fired.append("phase")
    if set(current.technologies) - set(previous.technologies):
        fired.append("technology")
    if set(current.cves[-SEARCHED_CVES:]) - set(previous.cves[-SEARCHED_CVES:]):
        fired.append("cve")
    return tuple(fired)
