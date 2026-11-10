#!/usr/bin/env python3
"""Check expected_results.yaml against the lab runs: PASS / FAIL per matrix ID (plan §11).

    python3 validate_urlscan_lab.py                      # report every ID from the stored evidence
    python3 validate_urlscan_lab.py --ids S-01,I2-01 -v  # some IDs, with every check line
    python3 validate_urlscan_lab.py --collect A          # freeze run A's graph evidence (run_lab.py does it)
    python3 validate_urlscan_lab.py --strict             # a skipped or incomplete ID also fails

Exit 1 on any FAIL (with --strict, also on SKIP / INCOMPLETE).

Evidence lives in generated/runs/<run>/ (written by run_lab.py): run.json, the
fake urlscan's log (urlscan_log.json), the hosts' hit logs (hits/), the scan
container's log (recon.log), the lab-hook names on the scan container
(container_env.json), and evidence.json. The graph changes with every later
run (P, A2 and the variants reuse project A), so the graph-side values
(cypher, recon_json, no_token, mcp) are collected right after each run and
frozen in evidence.json; the log-side checks are read at report time.

The graph is read through cypher-shell inside redamon-neo4j (labkit.cypher_rows):
the password stays in that container, muted nodes are included. Planted values
are compared inside this process and reported by label only (T1, K1...), never
printed.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import labkit  # noqa: E402

EXPECTED = labkit.HERE / "expected_results.yaml"
ASSERTIONS = ("equals", "superset", "disjoint", "true", "count", "min", "max")
LOG_KINDS = ("hits", "urlscan_log", "scan_log", "container_env")
GRAPH_KINDS = ("cypher", "recon_json", "no_token", "mcp")
INFO_KINDS = ("unit", "manual", "local")


def load_expected(path: Path = EXPECTED) -> list[dict]:
    spec = labkit.load_yaml(path.read_text(encoding="utf-8"))
    return spec["rows"]


def check_kind(check: dict) -> str:
    for kind in GRAPH_KINDS + LOG_KINDS + INFO_KINDS + ("compare", "see"):
        if kind in check:
            return kind
    raise ValueError(f"check without a kind: {check}")


def check_runs(row: dict, check: dict) -> list[str]:
    return list(check.get("runs") or row.get("runs") or [])


# --------------------------------------------------------------------------- run evidence on disk

def run_dir(run: str) -> Path:
    return labkit.RUNS / run


def run_info(run: str) -> dict | None:
    path = run_dir(run) / "run.json"
    return json.loads(path.read_text()) if path.is_file() else None


def _sub_runs(run: str) -> list[Path]:
    """P is the union of the partial runs' folders (P-Urlscan, P-Httpx, ...)."""
    if run == "P":
        return sorted(p for p in labkit.RUNS.glob("P-*") if p.is_dir())
    return [run_dir(run)]


def read_hits(run: str) -> list[dict]:
    out = []
    for d in _sub_runs(run):
        for f in sorted((d / "hits").glob("*.jsonl")):
            for line in f.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                entry.setdefault("container", f.stem)
                out.append(entry)
    return out


def read_urlscan_log(run: str) -> list[dict]:
    out = []
    for d in _sub_runs(run):
        f = d / "urlscan_log.json"
        if f.is_file():
            out.extend(json.loads(f.read_text()))
    return out


def read_scan_log(run: str) -> str:
    texts = []
    for d in _sub_runs(run):
        for f in sorted(d.glob("*.log")):
            texts.append(f.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(texts)


def evidence(run: str) -> dict:
    f = run_dir(run) / "evidence.json"
    return json.loads(f.read_text()) if f.is_file() else {}


# --------------------------------------------------------------------------- assertions

def bounded(n: int, spec: dict) -> tuple[bool, str]:
    if "count" in spec:
        return n == spec["count"], f"{n} (want {spec['count']})"
    lo, hi = spec.get("min"), spec.get("max")
    ok = (lo is None or n >= lo) and (hi is None or n <= hi)
    return ok, f"{n} (want {'>=' + str(lo) if lo is not None else ''}{' ' if lo is not None and hi is not None else ''}{'<=' + str(hi) if hi is not None else ''})"


def assert_values(check: dict, values: list) -> tuple[bool, str]:
    got = set(map(str, values))
    if "equals" in check:
        want = set(map(str, check["equals"]))
        return got == want, f"missing={sorted(want - got)} extra={sorted(got - want)[:10]}"
    if "superset" in check:
        missing = sorted(set(map(str, check["superset"])) - got)
        return not missing, f"missing={missing}"
    if "disjoint" in check:
        present = sorted(set(map(str, check["disjoint"])) & got)
        return not present, f"present={present}"
    if "true" in check:
        return values == [True], f"rows={values[:5]}"
    if any(k in check for k in ("count", "min", "max")):
        ok, detail = bounded(len(values), check)
        return ok, f"rows={detail} sample={[str(v)[:80] for v in values[:3]]}"
    raise ValueError(f"no assertion in {check}")


def _host(entry: dict) -> str:
    return str(entry.get("host") or "").split(":", 1)[0].lower().rstrip(".")


def eval_hits(spec: dict, run: str, values: dict) -> tuple[bool, str]:
    rx = re.compile(labkit.substitute(spec["uri_regex"], values)) if spec.get("uri_regex") else None
    n = 0
    for e in read_hits(run):
        if spec.get("container", "*") != "*" and e.get("container") != spec["container"]:
            continue
        if spec.get("method") and str(e.get("method", "")).upper() != spec["method"].upper():
            continue
        if spec.get("host") and _host(e) != spec["host"].lower():
            continue
        if rx and not rx.search(str(e.get("uri", ""))):
            continue
        n += 1
    ok, detail = bounded(n, spec)
    # The matched request targets may hold a planted value: report the count only.
    return ok, f"matching requests: {detail}"


def eval_urlscan_log(spec: dict, run: str, values: dict) -> tuple[bool, str]:
    rx = re.compile(labkit.substitute(spec["query_regex"], values))
    hits = [e for e in read_urlscan_log(run) if rx.search(e.get("query") or "")
            and ("key_sent" not in spec or bool(e.get("key_sent")) == spec["key_sent"])
            and ("search_after" not in spec or bool(e.get("search_after")) == spec["search_after"])]
    ok, detail = bounded(len(hits), spec)
    return ok, f"searches: {detail}"


def eval_scan_log(spec: dict, run: str) -> tuple[bool, str]:
    rx = re.compile(spec["regex"])
    n = sum(1 for line in read_scan_log(run).splitlines() if rx.search(line))
    ok, detail = bounded(n, spec)
    return ok, f"log lines: {detail}"


def eval_container_env(spec: dict, run: str) -> tuple[bool | None, str]:
    f = run_dir(run) / "container_env.json"
    if not f.is_file():
        return None, "no container_env.json (the scan container was never seen)"
    hooks = set(json.loads(f.read_text()).get("hooks") or [])
    bad = sorted(set(spec.get("absent", [])) & hooks) + sorted(set(spec.get("present", [])) - hooks)
    return not bad, f"hooks on the scan container: {sorted(hooks)}"


# --------------------------------------------------------------------------- collection (graph side)

def _graph_value_key(row_id: str, index: int, run: str) -> str:
    return f"{row_id}#{index}@{run}"


def _display_stripped(value):
    """`value` without the display-only fields (graph_db/display_only.py): the
    secret and the full links RedAmon keeps for the operator on purpose. The
    module is loaded from its file: the graph_db package needs the neo4j
    driver, which the host may not have."""
    module = getattr(_display_stripped, "module", None)
    if module is None:
        import importlib.util
        spec = importlib.util.spec_from_file_location(
            "display_only", labkit.REPO / "graph_db" / "display_only.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        _display_stripped.module = module
    return module.strip_display_only(value)


def _no_token_scan(pid: str, run: str, tokens: dict, labels: list[str]) -> dict:
    """Where a planted value appears outside the display-only fields: a graph
    property, a recon JSON field, a request a lab host received, a scan log."""
    wanted = {label: tokens[label] for label in labels}
    # A JWT's signature is unique to it; the header is shared by every HS256 JWT.
    needles = {label: [v] + ([v.rsplit(".", 1)[-1]] if v.count(".") == 2 else []) for label, v in wanted.items()}
    found: dict[str, set] = {label: set() for label in wanted}

    def scan(text: str, where: str):
        for label, parts in needles.items():
            if any(p and p in text for p in parts):
                found[label].add(where)

    for row in labkit.cypher_rows("MATCH (n {project_id: $pid}) RETURN {l: labels(n), p: properties(n)} AS v", pid):
        scan(json.dumps(_display_stripped(row.get("p"))), "graph:" + ",".join(row.get("l") or []))
    for row in labkit.cypher_rows("MATCH (a {project_id: $pid})-[r]->(b {project_id: $pid}) "
                                  "RETURN {t: type(r), p: properties(r)} AS v", pid):
        scan(json.dumps(row.get("p")), "graph:" + str(row.get("t")))
    for f in (labkit.REPO / "recon" / "output").glob(f"*{pid}*"):
        if f.is_file():
            text = f.read_text(encoding="utf-8", errors="replace")
            try:
                text = json.dumps(_display_stripped(json.loads(text)))
            except ValueError:
                pass
            scan(text, f"recon_json:{f.name}")
    for e in read_hits(run):
        scan(str(e.get("uri", "")), f"hits:{e.get('container')}")
    scan(read_scan_log(run), "scan_log")
    return {label: sorted(where) for label, where in found.items()}


def _recon_json_values(pid: str, path: str) -> list:
    node = json.loads((labkit.REPO / "recon" / "output" / f"recon_{pid}.json").read_text())
    for key in path.split("."):
        node = node.get(key) if isinstance(node, dict) else None
    if isinstance(node, dict):
        return list(node)
    if isinstance(node, list):
        return node
    return [] if node is None else [node]


def _mcp_text(tool: str, args: dict, pid: str) -> str:
    fp = labkit.HERE.parent / "fp_regression_target"
    sys.path.insert(0, str(fp))
    import mcp_client  # noqa: E402  (reads MCP_SERVER_TOKEN from .env by name, never prints it)
    if not getattr(_mcp_text, "ready", False):
        mcp_client.init()
        _mcp_text.ready = True
    out, err = mcp_client.call(tool, {k: (pid if v == "$pid" else v) for k, v in (args or {}).items()})
    text = out if isinstance(out, str) else json.dumps(out)
    if err:
        raise RuntimeError(f"{tool} answered an error: {text[:200]}")
    return text


def effective_runs(rows: list[dict]) -> dict[tuple[str, int], set[str]]:
    """(row id, check index) -> every run the check is evaluated on, including the
    runs a `see:` row borrows it for (B03 checks S-07's queries on run P)."""
    by_id = {r["id"]: r for r in rows}
    out: dict[tuple[str, int], set[str]] = {}

    def add(row: dict, runs: list[str] | None, depth: int = 0):
        for i, check in enumerate(row.get("checks", [])):
            kind = check_kind(check)
            if kind == "see":
                for ref in check["see"]:
                    if ref in by_id and depth < 3:
                        add(by_id[ref], runs or check_runs(row, check), depth + 1)
                continue
            if kind == "compare":
                wanted = _compare_runs(check)
            elif runs is None:
                wanted = check_runs(row, check)
            else:
                wanted = [r for r in check["runs"] if r in runs] if check.get("runs") else list(runs)
            out.setdefault((row["id"], i), set()).update(wanted)

    for row in rows:
        add(row, None)
    return out


def collect(run: str, rows: list[dict] | None = None, verbose: bool = True) -> dict:
    """Evaluate the graph-side checks that name `run` and freeze their values."""
    info = run_info(run)
    if not info or not info.get("project_id"):
        raise SystemExit(f"[!] {run_dir(run)}/run.json has no project_id: run it with run_lab.py first")
    pid = labkit.check_pid(info["project_id"])
    rows = rows or load_expected()
    tokens = labkit.load_tokens()
    wanted = effective_runs(rows)
    out = evidence(run)
    for row in rows:
        for i, check in enumerate(row.get("checks", [])):
            kind = check_kind(check)
            if kind == "compare":
                cypher = check["compare"]["cypher"]
            elif kind in GRAPH_KINDS:
                cypher = check.get("cypher")
            else:
                continue
            if run not in wanted.get((row["id"], i), set()):
                continue
            key = _graph_value_key(row["id"], i, run)
            try:
                if kind in ("cypher", "compare"):
                    out[key] = {"values": labkit.cypher_rows(cypher, pid)}
                elif kind == "recon_json":
                    out[key] = {"values": _recon_json_values(pid, check["recon_json"])}
                elif kind == "no_token":
                    out[key] = {"found": _no_token_scan(pid, run, tokens, check["no_token"])}
                elif kind == "mcp":
                    out[key] = {"text": _mcp_text(check["mcp"]["tool"], check["mcp"].get("args"), pid)}
            except (RuntimeError, OSError, ValueError, KeyError) as e:
                out[key] = {"error": str(e)[:300]}
            if verbose and "error" in out[key]:
                print(f"[!] {key}: {out[key]['error']}")
    run_dir(run).mkdir(parents=True, exist_ok=True)
    (run_dir(run) / "evidence.json").write_text(json.dumps(out, indent=1, default=str))
    if verbose:
        print(f"[+] {run}: {len(out)} graph value(s) frozen in {run_dir(run) / 'evidence.json'}")
    return out


def _compare_runs(check: dict) -> list[str]:
    spec = check["compare"]
    for mode in ("same", "subset", "disjoint"):
        if mode in spec:
            return list(spec[mode])
    raise ValueError(f"compare without same/subset/disjoint: {spec}")


# --------------------------------------------------------------------------- report

def eval_check(row: dict, index: int, check: dict, run: str | None, values: dict) -> tuple[str, str]:
    """(status, detail); status is PASS, FAIL, SKIP, UNIT, MANUAL or LOCAL."""
    kind = check_kind(check)
    if kind == "unit":
        return "UNIT", str(check["unit"])
    if kind == "manual":
        return "MANUAL", str(check["manual"])
    if kind == "local":
        return "LOCAL", str(check["local"])
    if kind == "compare":
        spec = check["compare"]
        runs = _compare_runs(check)
        sets = []
        for r in runs:
            ev = evidence(r).get(_graph_value_key(row["id"], index, r))
            if not ev or "values" not in ev:
                return "SKIP", f"no frozen values for run {r}"
            sets.append(set(map(str, ev["values"])))
        a, b = sets
        if not a or not b:
            return "FAIL", f"empty set ({len(a)} / {len(b)} values)"
        if "same" in spec:
            return ("PASS" if a == b else "FAIL"), f"{len(a ^ b)} value(s) differ"
        if "subset" in spec:
            return ("PASS" if a <= b else "FAIL"), f"{len(a - b)} value(s) of {runs[0]} missing in {runs[1]}"
        return ("PASS" if not a & b else "FAIL"), f"{len(a & b)} value(s) shared"
    if run is None or run_info(run) is None:
        return "SKIP", f"run {run} not done"
    if kind == "hits":
        ok, detail = eval_hits(check["hits"], run, values)
    elif kind == "urlscan_log":
        ok, detail = eval_urlscan_log(check["urlscan_log"], run, values)
    elif kind == "scan_log":
        ok, detail = eval_scan_log(check["scan_log"], run)
    elif kind == "container_env":
        ok, detail = eval_container_env(check["container_env"], run)
        if ok is None:
            return "SKIP", detail
    else:
        ev = evidence(run).get(_graph_value_key(row["id"], index, run))
        if not ev:
            return "SKIP", f"not collected for {run} (validate_urlscan_lab.py --collect {run})"
        if "error" in ev:
            return "FAIL", f"query failed: {ev['error']}"
        if kind == "no_token":
            leaks = {label: where for label, where in ev["found"].items() if where}
            return ("PASS" if not leaks else "FAIL"), (f"found {leaks}" if leaks else "no planted value found")
        if kind == "mcp":
            missing = [w for w in check["mcp"]["contains"] if w not in ev["text"]]
            return ("PASS" if not missing else "FAIL"), f"missing={missing}"
        ok, detail = assert_values(check, ev["values"])
    return ("PASS" if ok else "FAIL"), detail


def eval_row(row: dict, by_id: dict, values: dict, runs_override: list[str] | None = None,
             depth: int = 0) -> list[tuple[str, str, str]]:
    """[(status, label, detail)] for every check of `row` on every run it names."""
    lines = []
    for i, check in enumerate(row.get("checks", [])):
        kind = check_kind(check)
        label = f"{row['id']}.{i + 1} {kind}"
        if kind == "see":
            for ref in check["see"]:
                if depth > 3 or ref not in by_id:
                    lines.append(("FAIL", label, f"unknown row {ref}"))
                    continue
                for status, sub, detail in eval_row(by_id[ref], by_id, values,
                                                    runs_override or check_runs(row, check), depth + 1):
                    lines.append((status, f"{label} -> {sub}", detail))
            continue
        if kind in INFO_KINDS or kind == "compare":
            status, detail = eval_check(row, i, check, None, values)
            lines.append((status, label, detail))
            continue
        runs = runs_override if runs_override is not None else check_runs(row, check)
        if runs_override is not None and check.get("runs"):
            runs = [r for r in check["runs"] if r in runs_override]
        for run in runs:
            status, detail = eval_check(row, i, check, run, values)
            lines.append((status, f"{label} [{run}]", detail))
    return lines


def row_status(lines: list[tuple[str, str, str]]) -> str:
    statuses = {s for s, _, _ in lines}
    if "FAIL" in statuses:
        return "FAIL"
    if "PASS" in statuses:
        return "INCOMPLETE" if "SKIP" in statuses else "PASS"
    if "SKIP" in statuses:
        return "SKIP"
    return "MANUAL" if "MANUAL" in statuses else ("UNIT" if "UNIT" in statuses else "LOCAL")


def run_local(name: str) -> tuple[str, str]:
    if name != "check_fixtures":
        return "FAIL", f"unknown local check {name}"
    import subprocess
    out = subprocess.run([sys.executable, "-I", str(labkit.HERE / "fake_urlscan" / "check_fixtures.py")],
                         capture_output=True, text=True)
    return ("PASS" if out.returncode == 0 else "FAIL"), (out.stdout.strip().splitlines() or ["no output"])[-1]


def report(rows: list[dict], ids: set[str] | None, verbose: bool, strict: bool) -> int:
    by_id = {r["id"]: r for r in rows}
    try:
        values = labkit.placeholders(labkit.load_tokens(), labkit.lab_meta())
    except (OSError, SystemExit) as e:
        print(f"[!] cannot read the generated lab ({e}); log-side checks with placeholders will fail")
        values = {}
    counts: dict[str, int] = {}
    worst = 0
    for row in rows:
        if ids and row["id"] not in ids:
            continue
        lines = []
        for status, label, detail in eval_row(row, by_id, values):
            if status == "LOCAL":
                status, detail = run_local(detail)
            lines.append((status, label, detail))
        status = row_status(lines)
        counts[status] = counts.get(status, 0) + 1
        runs = ",".join(row.get("runs") or []) or "-"
        print(f"{status:<10} {row['id']:<14} [{runs}] {row.get('proves', '')}")
        for s, label, detail in lines:
            if verbose or s in ("FAIL", "SKIP"):
                print(f"    {s:<7} {label}: {detail}")
        if status == "FAIL" or (strict and status in ("SKIP", "INCOMPLETE")):
            worst = 1
    print("\n" + ", ".join(f"{k} {v}" for k, v in sorted(counts.items())))
    return worst


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--collect", metavar="RUN", help="freeze the graph-side values of one run")
    ap.add_argument("--ids", help="comma-separated matrix IDs")
    ap.add_argument("-v", "--verbose", action="store_true", help="print every check line")
    ap.add_argument("--strict", action="store_true", help="SKIP and INCOMPLETE fail too")
    a = ap.parse_args()
    rows = load_expected()
    if a.collect:
        collect(a.collect, rows)
        return 0
    ids = {s.strip() for s in a.ids.split(",")} if a.ids else None
    return report(rows, ids, a.verbose, a.strict)


if __name__ == "__main__":
    sys.exit(main())
