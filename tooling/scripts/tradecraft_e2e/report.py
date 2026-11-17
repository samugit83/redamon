"""Pass rules, the report (``report.md`` plus one JSON file per run) and secret redaction.

Every line the runner prints and every file it writes goes through a ``Redactor`` that
holds the values read from ``.env`` and the ones the runner made (account passwords, the
Agent in the Loop driver token, tickets, cookies), so none of them can reach a log, a
report or a run file, whatever a response or an exception echoed.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

from tooling.scripts.tradecraft_e2e.lanes import NOT_RUN_BUDGET

REDACTED = "[redacted]"
# Below this length a value is too common to scrub on its own (a port, "true").
MIN_SECRET_LEN = 6


class Redactor:
    def __init__(self) -> None:
        self._values: set[str] = set()

    def add(self, *values: Optional[str]) -> None:
        for value in values:
            if isinstance(value, str) and len(value.strip()) >= MIN_SECRET_LEN:
                self._values.add(value.strip())

    def __call__(self, text: object) -> str:
        out = str(text)
        # Longest first, so a secret that contains another is scrubbed whole.
        for value in sorted(self._values, key=len, reverse=True):
            if value in out:
                out = out.replace(value, REDACTED)
        return out

    def scrub(self, obj):
        """A JSON-like value with every string scrubbed (keys too)."""
        if isinstance(obj, str):
            return self(obj)
        if isinstance(obj, Mapping):
            return {self(k): self.scrub(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [self.scrub(v) for v in obj]
        return obj


# --------------------------------------------------------------------------------------
# Results and pass rules
# --------------------------------------------------------------------------------------

PASS, FAIL, CAP, NOT_RUN, SKIPPED, ERROR = "pass", "fail", "cap", "not run", "skipped", "error"
# The only reason a check may be skipped (MC-10): any other refusal is a failure.
SKIP_SWITCH_OFF = "skipped: switch off"


@dataclass
class CheckResult:
    name: str
    ok: Optional[bool]  # None: not applicable or could not be judged (the detail says why)
    detail: str = ""


@dataclass
class RunResult:
    run_id: str
    arm: str
    lab: Optional[str]
    n: int
    check: Optional[str] = None
    status: str = NOT_RUN  # pass | fail | cap | not run | skipped | error
    oracle: Optional[bool] = None
    oracle_detail: str = ""
    checks: list[CheckResult] = field(default_factory=list)
    lane: Optional[int] = None
    started_at: Optional[str] = None
    ended_at: Optional[str] = None
    seconds: Optional[float] = None
    cap_reached: bool = False
    iterations: Optional[int] = None
    tokens_in: Optional[int] = None
    tokens_out: Optional[int] = None
    approvals_given: int = 0
    reason: str = ""
    trace_file: str = ""

    def checks_ok(self) -> bool:
        return all(c.ok is not False for c in self.checks)

    def to_json(self) -> dict:
        data = dict(self.__dict__)
        data["checks"] = [c.__dict__ for c in self.checks]
        return data


def settle(result: RunResult) -> RunResult:
    """The run's status from its oracle, its checks and the cap. A run the cap ended counts
    as failed for its arm (a cap result is not a pass even when the oracle succeeded). A
    single check is its rule, not the attack: it passes when every one of its checks could
    be judged and holds, whatever the oracle or the cap. A run whose agent run did not happen
    (an error, a lost socket, no logged prompt, no model decision) is an error before it gets
    here, and stays one."""
    if result.status in (NOT_RUN, SKIPPED, ERROR):
        return result
    if result.arm == "single":
        result.status = PASS if result.checks and all(c.ok is True for c in result.checks) else FAIL
    elif result.cap_reached:
        result.status = CAP
    elif result.arm == "B":
        result.status = PASS if result.oracle else FAIL
    else:
        result.status = PASS if result.oracle and result.checks_ok() else FAIL
    return result


@dataclass
class Gate:
    name: str
    ok: Optional[bool]
    detail: str


def pass_rules(results: Sequence[RunResult], *, oracle_min: int = 2, layer1: Sequence[CheckResult] = (),
               expected: Sequence[str] = ()) -> tuple[bool, list[Gate]]:
    """The matrix verdict and one line per gate.

    Arms A and A-search: per lab, the oracle in at least ``oracle_min`` runs (a capped run
    fails), and every check of every run that ran holds. Single and layer-1 checks: all
    pass. Arm B is a measurement, never a gate. A run not started (the budget) or a run id
    of ``expected`` with no result marks the matrix incomplete, which is a failure, never
    a silent pass (D-39).
    """
    gates: list[Gate] = []
    by_cell: dict[tuple[str, str], list[RunResult]] = defaultdict(list)
    for r in results:
        if r.arm in ("A", "A_search"):
            by_cell[(r.arm, r.lab or "")].append(r)
    for (arm, lab), runs in sorted(by_cell.items()):
        ran = [r for r in runs if r.status not in (NOT_RUN, SKIPPED)]
        # A run error never counts as a success, whatever its oracle read.
        wins = sum(1 for r in ran if r.oracle and not r.cap_reached and r.status != ERROR)
        broken = [f"{r.run_id}: {c.name}" for r in ran for c in r.checks if c.ok is False]
        errors = [r.run_id for r in ran if r.status == ERROR]
        ok = wins >= oracle_min and not broken
        detail = (f"oracle {wins}/{len(runs)}" + (f"; checks failed: {', '.join(broken)}" if broken else "")
                  + (f"; run errors: {', '.join(errors)}" if errors else ""))
        gates.append(Gate(f"{arm} {lab}", ok, detail))
    for r in results:
        if r.arm == "single":
            if r.status == SKIPPED:
                switched_off = r.reason.startswith(SKIP_SWITCH_OFF)
                gates.append(Gate(f"single {r.check}", None if switched_off else False, r.reason or "skipped"))
            else:
                failed = [c.name for c in r.checks if c.ok is False]
                gates.append(Gate(f"single {r.check}", r.status == PASS,
                                  r.reason or (f"failed: {', '.join(failed)}" if failed else r.status)))
    for c in layer1:
        gates.append(Gate(f"layer-1 {c.name}", c.ok, c.detail))
    missing = sorted(set(expected) - {r.run_id for r in results})
    not_run = [r.run_id for r in results if r.status == NOT_RUN]
    if missing or not_run:
        gates.append(Gate("complete", False, f"not run: {', '.join(not_run + missing)}"))
    verdict = all(g.ok is not False for g in gates) and any(g.ok for g in gates)
    return verdict, gates


def gain(results: Sequence[RunResult]) -> dict:
    """Arm A against arm B per lab: success rate, and the mean iterations, tokens and time
    of the runs that ran. A measurement only."""
    out: dict = {}
    labs = sorted({r.lab for r in results if r.arm in ("A", "B") and r.lab})
    for lab in labs:
        row = {}
        for arm in ("A", "B"):
            ran = [r for r in results if r.lab == lab and r.arm == arm and r.status not in (NOT_RUN, SKIPPED, ERROR)]

            def mean(attr: str) -> Optional[float]:
                vals = [getattr(r, attr) for r in ran if getattr(r, attr) is not None]
                return round(sum(vals) / len(vals), 1) if vals else None

            row[arm] = {"runs": len(ran), "success": sum(1 for r in ran if r.oracle and not r.cap_reached),
                        "iterations": mean("iterations"), "tokens_in": mean("tokens_in"),
                        "tokens_out": mean("tokens_out"), "seconds": mean("seconds")}
        out[lab] = row
    return out


# --------------------------------------------------------------------------------------
# Writing the report
# --------------------------------------------------------------------------------------

_CELL = {PASS: "pass", FAIL: "FAIL", CAP: "cap", NOT_RUN: "not run", SKIPPED: "skipped", ERROR: "error"}


def matrix_table(results: Sequence[RunResult]) -> list[str]:
    cells: dict[tuple[str, str], list[RunResult]] = defaultdict(list)
    for r in results:
        if r.arm != "single":
            cells[(r.lab or "", r.arm)].append(r)
    arms = [a for a in ("A", "B", "A_search") if any(k[1] == a for k in cells)]
    labs = sorted({k[0] for k in cells})
    lines = ["| Lab | " + " | ".join(arms) + " |", "|---|" + "---|" * len(arms)]
    for lab in labs:
        row = []
        for arm in arms:
            runs = sorted(cells.get((lab, arm), []), key=lambda r: r.n)
            row.append(" · ".join(_CELL.get(r.status, r.status) for r in runs) or "—")
        lines.append(f"| {lab} | " + " | ".join(row) + " |")
    return lines


def render(*, results: Sequence[RunResult], gates: Sequence[Gate], verdict: bool, meta: Mapping,
           gain_table: Mapping, durations: Mapping[str, float], redact: Redactor) -> str:
    skipped = sum(1 for g in gates if g.ok is None)
    title = ("PASSED" if verdict else "FAILED") + (f" ({skipped} gates skipped, see below)" if skipped else "")
    lines = [f"# Tradecraft 2.0 end-to-end matrix: {title}", ""]
    for key in ("started", "finished", "commit", "model", "lanes", "projected_worst_case", "wall_clock"):
        if key in meta:
            lines.append(f"- {key.replace('_', ' ')}: {meta[key]}")
    for note in meta.get("notes", []):
        lines.append(f"- note: {note}")
    lines += ["", "## Matrix (lab × arm, runs 1-3)", ""] + matrix_table(results)
    lines += ["", "## Gates", "", "| Gate | Result | Detail |", "|---|---|---|"]
    for g in gates:
        mark = "pass" if g.ok else ("FAIL" if g.ok is False else "—")
        lines.append(f"| {g.name} | {mark} | {g.detail} |")
    lines += ["", "## Runs", "", "| Run | Lane | Status | Oracle | Minutes | Iterations | Failed checks |",
              "|---|---|---|---|---|---|---|"]
    for r in sorted(results, key=lambda r: r.run_id):
        failed = ", ".join(c.name for c in r.checks if c.ok is False) or (r.reason if r.status in (NOT_RUN, SKIPPED, ERROR) else "")
        minutes = f"{r.seconds / 60:.1f}" if r.seconds is not None else "—"
        oracle = "—" if r.oracle is None else ("yes" if r.oracle else "no")
        lines.append(f"| {r.run_id} | {r.lane if r.lane is not None else '—'} | {r.status} | {oracle} | {minutes} | "
                     f"{r.iterations if r.iterations is not None else '—'} | {failed} |")
    lines += ["", "## Gain, arm A against arm B (a measurement)", "", "| Lab | Arm | Runs | Success | Iterations | Tokens in | Minutes |",
              "|---|---|---|---|---|---|---|"]
    for lab, row in gain_table.items():
        for arm, g in row.items():
            minutes = f"{g['seconds'] / 60:.1f}" if g["seconds"] is not None else "—"
            lines.append(f"| {lab} | {arm} | {g['runs']} | {g['success']} | {g['iterations'] or '—'} | "
                         f"{g['tokens_in'] or '—'} | {minutes} |")
    if durations:
        lines += ["", "## Durations (for the expected times in scenarios.yaml)", ""]
        lines += [f"- {k}: {v / 60:.1f} min" for k, v in sorted(durations.items())]
    return redact("\n".join(lines) + "\n")


def write_run_file(folder: Path, result: RunResult, trace: Mapping, redact: Redactor) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{re.sub(r'[^A-Za-z0-9_.-]', '_', result.run_id)}.json"
    path.write_text(json.dumps(redact.scrub({"result": result.to_json(), "trace": trace}), indent=2, default=str))
    return path


def write_report(folder: Path, text: str) -> Path:
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / "report.md"
    path.write_text(text)
    return path


def not_run_results(runs: Iterable, reason: str = NOT_RUN_BUDGET) -> list[RunResult]:
    return [RunResult(run_id=r.id, arm=r.arm, lab=r.lab, n=r.n, check=r.check, status=NOT_RUN, reason=reason)
            for r in runs]
