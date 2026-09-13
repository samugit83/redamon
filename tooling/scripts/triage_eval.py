#!/usr/bin/env python3
"""Measure how good the Priority Board's order actually is.

WHY THIS EXISTS
Every change to the score model is an opinion until something checks it against
findings a human graded. This reads `testing/guinea_pigs/triage_truth.yaml`,
reads the findings a real triage run left in the graph, and prints the numbers
the release gate uses:

  NDCG@25          is the right thing near the top, discounted by position
  precision@10/25  what fraction of the top N is worth acting on
  rank of each known-real finding
  false-positive flag rate      how much the AI marks as noise
  real-flagged-as-false rate    the one that must stay at zero
  unclear rate                  how often the AI declines to judge
  LLM calls                     what the run cost

USAGE
  # offline, from a saved dump (what the unit tests exercise)
  triage_eval.py --guinea-pig apache_2.4.49 --findings findings.json

  # against the live stack
  triage_eval.py --guinea-pig apache_2.4.49 --user <id> --project <id>

  # the synthetic fixture that mirrors the dev graph's shape (no network)
  triage_eval.py --synthetic

  # every guinea pig named in _local/triage_eval_projects.yaml
  triage_eval.py --all

`--all` needs a mapping of guinea pig name -> {user, project}, which is
environment-specific and therefore NOT in the repository. Put it in
`_local/triage_eval_projects.yaml`:

  apache_2.4.49:
    user: <user id>
    project: <project id>

NOTHING HERE CONTACTS A TARGET. It reads the graph and a YAML file.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import random
import sys
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
TRUTH_FILE = REPO_ROOT / "testing" / "guinea_pigs" / "triage_truth.yaml"
PROJECT_MAP_FILE = REPO_ROOT / "_local" / "triage_eval_projects.yaml"

#: Grades at or above this count as "relevant" for precision@k. Grade 1
#: (hardening, information disclosure) is real but is not what an operator
#: opened the board to find, so precision measures grade >= 2.
RELEVANT_GRADE = 2


# ---------------------------------------------------------------------------
# Truth matching
# ---------------------------------------------------------------------------
#: Which finding fields each truth key is matched against. A finding matches an
#: entry when the key's value appears in ANY of these fields, so one entry
#: covers the several shapes the writers use for the same fact.
KEY_FIELDS = {
    "template": ("template_id", "name", "id"),
    "cve": ("cve_ids", "name", "id", "description"),
    "advisory": ("id", "name"),
    "type": ("type", "name", "id", "category"),
    "oid": ("id", "oid"),
    "detector": ("detector_name", "secret_type", "name"),
}


def _haystack(finding: dict, fields: tuple[str, ...]) -> str:
    parts = []
    for field in fields:
        value = finding.get(field)
        if isinstance(value, (list, tuple)):
            parts.extend(str(v) for v in value)
        elif value is not None:
            parts.append(str(value))
    return " ".join(parts).lower()


def grade_of(finding: dict, truth_entries: list[dict]) -> int | None:
    """The graded value of one finding, or None when the truth file is silent.

    An unknown finding is NOT scored as irrelevant: an incomplete truth file
    would otherwise look like a bad model. It is excluded, and `coverage` in the
    report says how many findings that was.
    """
    for entry in truth_entries:
        for key, fields in KEY_FIELDS.items():
            needle = entry.get(key)
            if not needle:
                continue
            hay = _haystack(finding, fields)
            needle = str(needle).lower()
            if entry.get("match") == "prefix":
                # A prefix entry (GHSA-, PYSEC-) matches an id that STARTS with
                # it, so it cannot accidentally swallow a description mentioning
                # the word somewhere in the middle.
                ident = str(finding.get("id") or "").lower()
                if ident.startswith(needle):
                    return int(entry["grade"])
            elif needle in hay:
                return int(entry["grade"])
    return None


# ---------------------------------------------------------------------------
# Metrics
# ---------------------------------------------------------------------------
def dcg(grades: list[int]) -> float:
    """Discounted cumulative gain with the 2^g - 1 gain function.

    A negative grade (a false positive that got ranked) is a real penalty
    rather than a zero: putting noise on the board is worse than omitting a
    finding, because it is what makes operators stop reading the board.
    """
    total = 0.0
    for index, grade in enumerate(grades, start=1):
        gain = (2 ** grade - 1) if grade >= 0 else -1.0
        total += gain / math.log2(index + 1)
    return total


def ndcg_at(graded_ranking: list[int], k: int) -> float | None:
    """NDCG@k, or None when there is nothing to measure.

    None, not 0.0. A project whose findings the truth file says nothing about
    is UNMEASURED, and 0.0 says "the worst possible ordering" - which the
    release gate would then read as a catastrophic regression caused by
    whatever changed last. The two have to be distinguishable.
    """
    if not graded_ranking:
        return None
    ideal = sorted(graded_ranking, reverse=True)[:k]
    ideal_dcg = dcg(ideal)
    if ideal_dcg <= 0:
        # Everything known about this board is a false positive or a
        # fingerprint, so there is no "right" order to score against.
        return None
    return dcg(graded_ranking[:k]) / ideal_dcg


def precision_at(graded_ranking: list[int], k: int) -> float:
    top = graded_ranking[:k]
    if not top:
        return 0.0
    return sum(1 for g in top if g >= RELEVANT_GRADE) / len(top)


def _round(value):
    return None if value is None else round(value, 4)


def evaluate(findings: list[dict], truth_entries: list[dict]) -> dict[str, Any]:
    """The full report for one project's findings, already in board order."""
    graded: list[int] = []
    known: list[tuple[int, dict, int]] = []   # (board rank, finding, grade)
    for rank, finding in enumerate(findings, start=1):
        grade = grade_of(finding, truth_entries)
        if grade is None:
            continue
        graded.append(grade)
        known.append((rank, finding, grade))

    verdicts = [str(f.get("triage_ai_verdict") or "").lower() for f in findings]
    statuses = [str(f.get("triage_status") or "").lower() for f in findings]
    flagged_noise = sum(
        1 for v, s in zip(verdicts, statuses)
        if v == "false_positive" or s == "likely_noise"
    )
    unclear = sum(1 for v in verdicts if v == "unclear")
    reviewed = sum(1 for v in verdicts if v and v != "not_reviewed")

    real_flagged_false = sum(
        1 for rank, finding, grade in known
        if grade >= RELEVANT_GRADE and (
            str(finding.get("triage_ai_verdict") or "").lower() == "false_positive"
            or str(finding.get("triage_status") or "").lower() == "likely_noise"
        )
    )
    known_false = [k for k in known if k[2] < 0]
    caught_false = sum(
        1 for rank, finding, grade in known_false
        if str(finding.get("triage_ai_verdict") or "").lower() == "false_positive"
        or str(finding.get("triage_status") or "").lower() == "likely_noise"
    )

    total = len(findings) or 1
    return {
        "findings": len(findings),
        "graded": len(graded),
        "coverage": round(len(graded) / total, 3),
        "ndcg@25": _round(ndcg_at(graded, 25)),
        "ndcg@10": _round(ndcg_at(graded, 10)),
        "precision@10": round(precision_at(graded, 10), 4),
        "precision@25": round(precision_at(graded, 25), 4),
        "ranks": [
            {
                "rank": rank,
                "grade": grade,
                "id": finding.get("id"),
                "name": str(finding.get("name") or "")[:70],
                "score": finding.get("triage_priority_score"),
                "tier": finding.get("triage_tier"),
                "verdict": finding.get("triage_ai_verdict"),
            }
            for rank, finding, grade in known
        ],
        "false_positive_flag_rate": round(flagged_noise / total, 4),
        "real_flagged_as_false": real_flagged_false,
        "known_false_positives": len(known_false),
        "known_false_positives_caught": caught_false,
        "unclear_rate": round(unclear / total, 4),
        "reviewed": reviewed,
    }


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------
def load_truth(path: Path = TRUTH_FILE) -> dict:
    import yaml
    with open(path) as handle:
        return yaml.safe_load(handle) or {}


def load_findings_file(path: Path) -> list[dict]:
    with open(path) as handle:
        data = json.load(handle)
    if isinstance(data, dict):
        data = data.get("findings", [])
    return [d for d in data if isinstance(d, dict)]


def load_findings_live(user_id: str, project_id: str) -> list[dict]:
    """Read the board exactly as the UI does, through the triage mixin."""
    sys.path.insert(0, str(REPO_ROOT))
    from graph_db.neo4j_client import Neo4jClient
    with Neo4jClient() as client:
        return client.list_triage_findings(user_id, project_id)


def synthetic_findings(seed: int = 20260911) -> list[dict]:
    """A fixture shaped like the live dev graph, ordered by nothing.

    94% OSV advisories, a block of GitHub "secrets" that are private IP
    addresses, a handful of real things. The point is not realism in the
    details; it is that the mix is dominated by low-value rows, which is what
    breaks a formula that adds points per signal.
    """
    rng = random.Random(seed)
    findings: list[dict] = []
    for i in range(419):
        findings.append({
            "id": f"PYSEC-2021-{i:04d}", "label": "Vulnerability",
            "name": f"PYSEC-2021-{i:04d}", "severity": "info", "source": "osv",
        })
    for i in range(200):
        findings.append({
            "id": f"GHSA-xxxx-{i:04d}-abcd", "label": "Vulnerability",
            "name": f"GHSA-xxxx-{i:04d}-abcd", "severity": "high", "source": "osv",
        })
    for i in range(119):
        findings.append({
            "id": f"ghsecret-priv-ip-{i:03d}", "label": "GithubSecret",
            "name": "IP Address (Private)", "detector_name": "IP Address (Private)",
            "secret_type": "IP Address (Private)", "severity": "high",
            "source": "github_hunt",
        })
    findings.append({
        "id": "ghsecret-aws-1", "label": "GithubSecret", "name": "AWS",
        "detector_name": "AWS", "secret_type": "AWS", "severity": "critical",
        "source": "github_hunt",
    })
    findings.append({
        "id": "MAL-2022-1122", "label": "MalPackageFinding",
        "name": "MAL-2022-1122", "severity": "critical", "source": "osv",
    })
    for i in range(73):
        findings.append({
            "id": f"check-hsts-{i:03d}", "label": "Vulnerability",
            "name": "missing_hsts", "type": "missing_hsts", "severity": "info",
            "source": "security_check",
        })
    rng.shuffle(findings)
    return findings


def load_project_map() -> dict:
    if not PROJECT_MAP_FILE.exists():
        return {}
    import yaml
    with open(PROJECT_MAP_FILE) as handle:
        return yaml.safe_load(handle) or {}


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def print_report(name: str, report: dict, show_ranks: bool = True) -> None:
    print(f"\n=== {name} ===")
    print(f"  findings {report['findings']}, graded {report['graded']} "
          f"(coverage {report['coverage']:.0%})")
    if report["ndcg@25"] is None:
        print("  NDCG: not measurable - the truth file grades none of these "
              "findings")
    else:
        print(f"  NDCG@25 {report['ndcg@25']:.4f}   "
              f"NDCG@10 {report['ndcg@10']:.4f}")
    print(f"  P@10 {report['precision@10']:.2f}   P@25 {report['precision@25']:.2f}")
    print(f"  flagged false positive: {report['false_positive_flag_rate']:.1%} "
          f"of all findings")
    print(f"  known false positives caught: "
          f"{report['known_false_positives_caught']}/{report['known_false_positives']}")
    print(f"  REAL findings wrongly flagged false: {report['real_flagged_as_false']}"
          f"{'   <-- release gate failure' if report['real_flagged_as_false'] else ''}")
    print(f"  unclear {report['unclear_rate']:.1%}, reviewed {report['reviewed']}")
    if show_ranks and report["ranks"]:
        print("  graded findings, in board order:")
        for row in report["ranks"][:40]:
            score = row["score"]
            score_text = f"{score:6.2f}" if isinstance(score, (int, float)) else "  n/a"
            print(f"    #{row['rank']:<4} grade {row['grade']:>2}  {score_text}  "
                  f"{row['tier'] or '--':<3} {row['name']}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--guinea-pig", help="key in triage_truth.yaml")
    parser.add_argument("--findings", type=Path,
                        help="JSON dump of list_triage_findings (offline mode)")
    parser.add_argument("--user", help="user id (live mode)")
    parser.add_argument("--project", help="project id (live mode)")
    parser.add_argument("--synthetic", action="store_true",
                        help="run against the dev-graph-shaped fixture")
    parser.add_argument("--all", action="store_true",
                        help="every guinea pig in _local/triage_eval_projects.yaml")
    parser.add_argument("--json", action="store_true", help="machine-readable output")
    parser.add_argument("--baseline", type=Path,
                        help="write the report here, to compare a later run against")
    parser.add_argument("--compare", type=Path,
                        help="a baseline file; exit 1 if NDCG@25 regressed")
    args = parser.parse_args(argv)

    truth = load_truth()
    reports: dict[str, dict] = {}

    def entries_for(key: str) -> list[dict]:
        section = truth.get(key) or {}
        return section.get("findings") or []

    if args.synthetic:
        reports["synthetic_dev_shape"] = evaluate(
            synthetic_findings(), entries_for("synthetic_dev_shape"))
    elif args.all:
        project_map = load_project_map()
        if not project_map:
            print(f"No {PROJECT_MAP_FILE.relative_to(REPO_ROOT)}; "
                  f"nothing to evaluate. See this script's docstring.",
                  file=sys.stderr)
            return 2
        for name, config in project_map.items():
            try:
                findings = load_findings_live(config["user"], config["project"])
            except Exception as exc:                      # noqa: BLE001
                print(f"{name}: could not read the graph ({exc})", file=sys.stderr)
                continue
            reports[name] = evaluate(findings, entries_for(name))
    else:
        if not args.guinea_pig:
            parser.error("--guinea-pig is required unless --all or --synthetic")
        if args.findings:
            findings = load_findings_file(args.findings)
        elif args.user and args.project:
            findings = load_findings_live(args.user, args.project)
        else:
            parser.error("give either --findings, or --user and --project")
        reports[args.guinea_pig] = evaluate(findings, entries_for(args.guinea_pig))

    if args.json:
        print(json.dumps(reports, indent=2))
    else:
        for name, report in reports.items():
            print_report(name, report)

    if args.baseline:
        args.baseline.parent.mkdir(parents=True, exist_ok=True)
        args.baseline.write_text(json.dumps(reports, indent=2))
        print(f"\nBaseline written to {args.baseline}")

    if args.compare:
        previous = json.loads(args.compare.read_text())
        regressed = []
        for name, report in reports.items():
            was = (previous.get(name) or {}).get("ndcg@25")
            now = report["ndcg@25"]
            if was is None or now is None:
                # One side is unmeasured, so there is no comparison to make.
                # Saying so beats inventing a verdict from a missing number.
                print(f"  {name}: not comparable (nothing graded on one side)")
            elif now < was - 1e-9:
                regressed.append(f"{name}: {was:.4f} -> {now:.4f}")
            if report["real_flagged_as_false"]:
                regressed.append(
                    f"{name}: {report['real_flagged_as_false']} real findings "
                    f"flagged as false positives")
        if regressed:
            print("\nRELEASE GATE FAILED:", file=sys.stderr)
            for line in regressed:
                print(f"  {line}", file=sys.stderr)
            return 1
        print("\nRelease gate passed.")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
