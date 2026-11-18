"""The matrix's runs and the scheduler that spreads them over parallel lanes.

Pure code: no Docker, no network, no clock of its own (the caller passes "now"), so the
5-hour arithmetic of the plan is tested here and printed by ``--dry-run``.

A lane runs one lab instance and one agent session at a time. Its lab front gets the
lane's own address on the pentest network and the lane's own host ports, so two runs at
the same moment never share either.

The owner's "Librarian use" is one setting of the e2e owner's account, read by every run
of that owner when it starts. Arm A-search needs "Search only", arms A and the single
checks need "Agent decides", arm B does not care (every resource is off in its projects).
So the scheduler keeps one mode at a time: the A-search runs go first, with mode-neutral
runs filling the free lanes, and the mode changes only once no run of the old mode is
running.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field, replace
from typing import Callable, Iterable, Mapping, Optional, Sequence

MODE_AGENT = "agent"
MODE_SEARCH_ONLY = "search_only"
MODE_ANY = "any"
NOT_RUN_BUDGET = "not run: budget"
PORTS_PER_LANE = 10


@dataclass(frozen=True)
class Run:
    id: str
    arm: str  # "A", "B", "A_search" or "single"
    lab: Optional[str]
    n: int
    cap_sec: int
    expected_sec: int
    mode: str = MODE_ANY
    check: Optional[str] = None
    agent: bool = True


@dataclass(frozen=True)
class Slot:
    run: Run
    lane: int
    start: float
    end: float


@dataclass
class Timeline:
    slots: list[Slot] = field(default_factory=list)
    not_run: list[tuple[Run, str]] = field(default_factory=list)
    mode_changes: list[tuple[float, str]] = field(default_factory=list)

    @property
    def makespan(self) -> float:
        return max((s.end for s in self.slots), default=0.0)

    def lanes_used(self) -> int:
        return len({s.lane for s in self.slots})


def _minutes(value: object, default: float) -> int:
    return int(round(float(value if value is not None else default) * 60))


def plan_runs(scn: Mapping) -> list[Run]:
    """Every run of the matrix, from ``scenarios.yaml``: the arms times their labs times their
    runs, then the single checks."""
    runs: list[Run] = []
    labs = scn["labs"]
    for arm, spec in scn["arms"].items():
        for lab in spec["labs"]:
            expected = labs[lab].get("expected_min", {}).get(arm, spec.get("expected_min", spec["cap_min"]))
            for n in range(1, int(spec["runs"]) + 1):
                runs.append(Run(id=f"{lab}-{arm}-{n}", arm=arm, lab=lab, n=n, cap_sec=_minutes(spec["cap_min"], 40),
                                expected_sec=_minutes(expected, 40), mode=spec.get("mode", MODE_ANY)))
    for check, spec in scn["singles"].items():
        runs.append(Run(id=check, arm="single", lab=spec.get("lab"), n=1, cap_sec=_minutes(spec.get("cap_min"), 20),
                        expected_sec=_minutes(spec.get("expected_min"), 10), mode=spec.get("mode", MODE_AGENT),
                        check=check, agent=bool(spec.get("agent", True))))
    return runs


def select(runs: Iterable[Run], only: Sequence[str] = ()) -> list[Run]:
    """``--only``: a run id (``L3-A-1``), a lab (``L3``), an arm (``A``, ``B``, ``A_search``,
    ``single``), a lab and arm (``L3-A``) or a single check (``S4``); several are a union."""
    runs = list(runs)
    if not only:
        return runs
    wanted = {o.strip() for o in only if o.strip()}

    def picked(r: Run) -> bool:
        keys = {r.id, r.arm, r.check or "", r.lab or "", f"{r.lab}-{r.arm}"}
        return bool(keys & wanted)

    return [r for r in runs if picked(r)]


def longest_first(runs: Iterable[Run]) -> list[Run]:
    return sorted(runs, key=lambda r: (-r.expected_sec, -r.cap_sec, r.id))


class Scheduler:
    """Which run a free lane starts next. ``next_run`` is asked whenever a lane is free, with
    the time since the matrix started (its preflight included); it returns None when nothing
    may start now: the budget guard has passed, no waiting run could end within the budget
    (``end_by_sec``), or a mode change waits for the runs of the old mode."""

    def __init__(self, runs: Iterable[Run], *, start_until_sec: float, end_by_sec: Optional[float] = None):
        self.pending: list[Run] = longest_first(runs)
        self.running: dict[str, Run] = {}
        self.mode: Optional[str] = None
        self.start_until_sec = start_until_sec
        self.end_by_sec = end_by_sec

    def _wanted_mode(self) -> Optional[str]:
        active = {r.mode for r in self.running.values() if r.mode != MODE_ANY}
        if active:
            return active.pop()
        if any(r.mode == MODE_SEARCH_ONLY for r in self.pending):
            return MODE_SEARCH_ONLY
        if any(r.mode == MODE_AGENT for r in self.pending):
            return MODE_AGENT
        return self.mode

    def next_run(self, elapsed_sec: float) -> Optional[Run]:
        if not self.pending or elapsed_sec >= self.start_until_sec:
            return None
        mode = self._wanted_mode()
        allowed = [r for r in self.pending if r.mode in (mode, MODE_ANY)]
        # While runs of another mode still wait, this mode's own runs go first, so they start
        # together and the change comes as early as it can; after the last change, longest first.
        if any(r.mode not in (mode, MODE_ANY) for r in self.pending):
            allowed.sort(key=lambda r: r.mode == MODE_ANY)
        if self.end_by_sec is not None:
            # A run's cap bounds its whole lane time: one that could end after the budget never starts.
            allowed = [r for r in allowed if elapsed_sec + r.cap_sec <= self.end_by_sec]
        choice = (allowed or [None])[0]
        if choice is None:
            return None
        self.pending.remove(choice)
        self.running[choice.id] = choice
        return choice

    def needs_mode(self, run: Run) -> Optional[str]:
        """The owner mode to set before ``run`` starts, or None when it is already in force."""
        if run.mode == MODE_ANY or run.mode == self.mode:
            return None
        return run.mode

    def mode_set(self, mode: str) -> None:
        self.mode = mode

    def finished(self, run: Run) -> None:
        self.running.pop(run.id, None)

    def not_started(self) -> list[Run]:
        return list(self.pending)


def simulate(runs: Iterable[Run], lanes: int, *, start_until_sec: float, end_by_sec: Optional[float] = None,
             offset_sec: float = 0.0, duration: Optional[Callable[[Run], float]] = None) -> Timeline:
    """The schedule the live runner would follow when every run takes ``duration(run)``
    seconds of its lane (default: its cap, the worst case), the lanes starting
    ``offset_sec`` after the matrix (the preflight)."""
    if lanes < 1:
        raise ValueError("at least one lane")
    took = duration or (lambda r: r.cap_sec)
    sched = Scheduler(runs, start_until_sec=start_until_sec, end_by_sec=end_by_sec)
    timeline = Timeline()
    free_at = [float(offset_sec)] * lanes
    ends: list[tuple[float, int, Run]] = []
    now = float(offset_sec)
    while True:
        started = False
        for lane in range(lanes):
            if free_at[lane] > now:
                continue
            run = sched.next_run(now)
            if run is None:
                break
            mode = sched.needs_mode(run)
            if mode:
                sched.mode_set(mode)
                timeline.mode_changes.append((now, mode))
            end = now + min(float(took(run)), float(run.cap_sec))
            timeline.slots.append(Slot(run, lane, now, end))
            free_at[lane] = end
            ends.append((end, lane, run))
            started = True
        if not ends:
            break
        if started:
            continue
        # Every run that ends at the earliest end time ends before any lane starts again, as
        # the live runner sees them when it next looks.
        ends.sort(key=lambda e: (e[0], e[1]))
        now = max(now, ends[0][0])
        while ends and ends[0][0] <= now:
            sched.finished(ends.pop(0)[2])
    timeline.not_run = [(r, NOT_RUN_BUDGET) for r in sched.not_started()]
    return timeline


@dataclass(frozen=True)
class Budget:
    """The matrix's clock, all from its start (the preflight included): no run starts after
    ``start_until_sec``, none that could end after ``end_by_sec`` (the total less the time to
    collect the results), and the lanes expect to start ``preflight_sec`` in."""
    start_until_sec: float
    end_by_sec: float
    preflight_sec: float
    total_sec: float


def budget(scn: Mapping) -> Budget:
    b = scn["budget"]
    total = float(b["total_min"]) * 60
    return Budget(start_until_sec=float(b["start_until_min"]) * 60, end_by_sec=total - float(b["collect_min"]) * 60,
                  preflight_sec=float(b["preflight_min"]) * 60, total_sec=total)


def worst_case(runs: Sequence[Run], lanes: int, plan: Budget, *, preflight_sec: Optional[float] = None) -> Timeline:
    """Every run at its cap (a run's whole lane time), the lanes starting after the preflight."""
    return simulate(runs, lanes, start_until_sec=plan.start_until_sec, end_by_sec=plan.end_by_sec,
                    offset_sec=plan.preflight_sec if preflight_sec is None else preflight_sec)


# --------------------------------------------------------------------------------------
# Lane addressing
# --------------------------------------------------------------------------------------

@dataclass(frozen=True)
class LaneAddressing:
    ip_base: str
    port_base: int
    lanes: int

    def ip(self, lane: int) -> str:
        self._check(lane)
        return str(ipaddress.ip_address(self.ip_base) + lane)

    def port(self, lane: int, k: int) -> int:
        self._check(lane)
        if not 0 <= k < PORTS_PER_LANE:
            raise ValueError(f"a lane has {PORTS_PER_LANE} host ports")
        return self.port_base + lane * PORTS_PER_LANE + k

    def _check(self, lane: int) -> None:
        if not 0 <= lane < self.lanes:
            raise ValueError(f"lane {lane} is outside 0..{self.lanes - 1}")


def addressing(scn: Mapping, lanes: int) -> LaneAddressing:
    cfg = scn["lanes"]
    return LaneAddressing(ip_base=str(cfg["ip_base"]), port_base=int(cfg["port_base"]), lanes=lanes)


def with_cap(run: Run, cap_sec: int) -> Run:
    return replace(run, cap_sec=cap_sec)
