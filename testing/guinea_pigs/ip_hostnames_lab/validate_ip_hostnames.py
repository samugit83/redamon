#!/usr/bin/env python3
"""Check expected_results.yaml against the lab's run evidence: PASS / FAIL per check.

    python3 validate_ip_hostnames.py --self-test                 # every operator, parser and reader on canned data
    python3 validate_ip_hostnames.py --list                      # rows, their steps and checks; contacts nothing
    python3 validate_ip_hostnames.py --row E0 --run-root generated/runs/E0-<stamp> [--out RESULTS.md]
    python3 validate_ip_hostnames.py --report [--out generated/RESULTS.md]   # latest run of every row

Exit 1 on any FAIL. e2e_ip_hostnames.py calls the same functions right after
each step, because the graph of a project changes with its next run: a `cypher`
check re-evaluated later reads the graph as it is THEN. Every other kind reads
files frozen in the step's folder.

A check is one evidence KIND, optional `where` / `field`, and one OPERATOR;
`step: <label>` names the step whose evidence it reads (default: the row's last run):

  kinds     cypher: <Cypher returning a column v>     MCP query_graph (token needs graph:cypher)
            recon_json: <dotted path | list>          the run's recon JSON; "*" walks every key
                                                      or item; `pairs: <subkey>` gives "<key>=<value>"
            hits: <container | all>                   nginx/edge hit lines of the step's window
            pcap: outsider                            packets the outsider received (default: dst .99, IPv4/6)
            dnslog: coredns                           queries in CoreDNS's log of the step's window
            scan_log: <regex>                         matching lines of the recon container's log
            run: <meta field>                         the step's meta.json (status, project_id ...)
            result: <dotted path>                     the step's result.json (an action's answer)
            manual: <text>                            not evaluated; reported as MANUAL
  where     {field: value | [any of] | "*" (non-empty) | null (empty) | {not: value}}
  field     project each row on one field (hits: host_name, sni, client, vhost, uri, status;
            pcap: src, dst, dport, proto, flags; dnslog: name, qtype, ptr_ip, client, rcode)
  operators equals | superset | subset | disjoint (sets of str), true (one row, true),
            count | min | max (number of rows), contains (substrings, case-insensitive),
            record (always PASS; the values go to RESULTS.md: the "before" picture)

In list operands "$targets" expands to the step's target list, "$outsider" to
192.88.98.99, "$intra" to iphn-intra's address. PyYAML is required (the host
has it; nested_wildcard_lab's validator uses it the same way).
"""
from __future__ import annotations

import argparse
import json
import re
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import iphn_lab  # noqa: E402

try:
    import yaml
except ImportError:  # pragma: no cover - the message is the point
    yaml = None

EXPECTED = iphn_lab.HERE / "expected_results.yaml"
KINDS = ("cypher", "recon_json", "hits", "pcap", "dnslog", "scan_log", "run", "result", "manual")
OPERATORS = ("equals", "superset", "subset", "disjoint", "true", "count", "min", "max", "contains", "record")
SET_OPS = ("equals", "superset", "subset", "disjoint")
ACTIONS = ("run", "partial", "partial_wait", "rescope", "mcp", "rest", "zone", "wait")
STEPS = ("P0", "P0a", "P0b", "P0c", "P1", "P2", "P3", "P4", "P5", "P6", "P7", "P8", "P9", "P10")
ROW_IDS = tuple(f"E{i}" for i in range(26))
ROW_KINDS = ("full", "governance", "external")


# --------------------------------------------------------------------------- the spec

def load_expected(path: Path = EXPECTED) -> dict:
    if yaml is None:
        raise SystemExit("[!][Validate] PyYAML is missing: python3 -m pip install --user pyyaml")
    return parse_spec(path.read_text(encoding="utf-8"))


def parse_spec(text: str) -> dict:
    spec = yaml.safe_load(text)
    if not isinstance(spec, dict) or not isinstance(spec.get("rows"), dict):
        raise ValueError("expected_results.yaml needs a `rows` mapping")
    return spec


def check_kind(check: dict) -> str:
    kinds = [k for k in KINDS if k in check]
    if len(kinds) != 1:
        raise ValueError(f"check {check.get('id')!r} needs exactly one kind of {KINDS}, has {kinds}")
    return kinds[0]


def check_operator(check: dict) -> str | None:
    ops = [o for o in OPERATORS if o in check]
    if check_kind(check) == "manual":
        return None
    if len(ops) != 1:
        raise ValueError(f"check {check.get('id')!r} needs exactly one operator of {OPERATORS}, has {ops}")
    return ops[0]


def sequence(row: dict) -> list[dict]:
    return row.get("sequence") or [{"run": "main"}]


def action_of(step: dict) -> str:
    names = [a for a in ACTIONS if a in step]
    if len(names) != 1:
        raise ValueError(f"sequence step {step} needs exactly one action of {ACTIONS}")
    return names[0]


def step_label(step: dict) -> str:
    action = action_of(step)
    if action == "run":
        return str(step["run"])
    if action == "partial_wait":
        return str(step["partial_wait"])
    return str(step.get("label") or f"{action}")


def projects(row: dict, spec: dict) -> dict:
    return row.get("projects") or {"main": {}}


def needs_steps(row: dict) -> list[str]:
    need = row.get("needs_step")
    if need is None:
        return []
    return [need] if isinstance(need, str) else list(need)


def checks_for(spec: dict, row_id: str, label: str, kind: str) -> list[dict]:
    """The checks evaluated after step `label` (of action `kind`) of row `row_id`."""
    row = spec["rows"][row_id]
    labels = [step_label(s) for s in sequence(row)]
    runs = [step_label(s) for s in sequence(row) if action_of(s) == "run"]
    default = runs[-1] if runs else (labels[-1] if labels else "main")
    out = []
    own = list(row.get("checks") or [])
    ref = row.get("same_checks_as")
    if ref:
        other = spec["rows"][ref["row"]]
        for c in other.get("checks") or []:
            if (c.get("step") or "main") == ref.get("step", "main"):
                own.append(dict(c, step=ref.get("as", default), id=f"{ref['row']}:{c['id']}"))
    for c in own:
        if (c.get("step") or default) == label:
            out.append(c)
    if row.get("common"):
        for c in spec.get("common_checks") or []:
            if kind in (c.get("applies") or ["run"]):
                out.append(dict(c, id=f"common:{c['id']}"))
    return out


def spec_problems(spec: dict) -> list[str]:
    """Structural problems of the expected results; [] when every row is usable."""
    problems = []
    rows = spec.get("rows") or {}
    for rid in ROW_IDS:
        if rid not in rows:
            problems.append(f"row {rid} is missing (06_testing.md §5 has E0-E25)")
    for rid, row in rows.items():
        where = f"row {rid}"
        if not isinstance(row, dict):
            problems.append(f"{where}: not a mapping")
            continue
        if not row.get("title"):
            problems.append(f"{where}: no title")
        if row.get("kind", "full") not in ROW_KINDS:
            problems.append(f"{where}: kind {row.get('kind')!r} not in {ROW_KINDS}")
        for s in needs_steps(row):
            if s not in STEPS:
                problems.append(f"{where}: needs_step {s!r} not in {STEPS}")
        if row.get("kind") == "external":
            if not row.get("how"):
                problems.append(f"{where}: an external row needs `how`")
            continue
        # YAML 1.1 (PyYAML) reads an unquoted on/off/yes/no/true key as a boolean:
        # `on: m2` silently became `True: m2` once already.
        for part in [row, *sequence(row), *(row.get("checks") or []), *projects(row, spec).values()]:
            if isinstance(part, dict) and any(isinstance(k, bool) for k in part):
                problems.append(f"{where}: a boolean key in {part} (quote it, e.g. \"true\":)")
        labels = set()
        try:
            for st in sequence(row):
                labels.add(step_label(st))
                act = action_of(st)
                on = st.get("project")
                if on and on not in projects(row, spec):
                    problems.append(f"{where}: step {step_label(st)!r} runs on unknown project {on!r}")
                if act == "partial" and not (st.get("partial") or {}).get("tool_id"):
                    problems.append(f"{where}: partial step {step_label(st)!r} has no tool_id")
        except ValueError as e:
            problems.append(f"{where}: {e}")
        for label, p in projects(row, spec).items():
            labels.add(f"create-{label}")
            if p.get("settings", {}).get("masscanEnabled"):
                problems.append(f"{where}: project {label} turns masscan on (it ignores the lab route)")
        if row.get("same_checks_as") and row["same_checks_as"].get("row") not in rows:
            problems.append(f"{where}: same_checks_as names an unknown row")
        seen = set()
        for c in row.get("checks") or []:
            cid = c.get("id")
            if not cid or cid in seen:
                problems.append(f"{where}: check id {cid!r} missing or repeated")
            seen.add(cid)
            try:
                check_kind(c)
                check_operator(c)
            except ValueError as e:
                problems.append(f"{where}: {e}")
            if c.get("step") and c["step"] not in labels:
                problems.append(f"{where}: check {cid!r} names unknown step {c['step']!r}")
    for c in spec.get("common_checks") or []:
        try:
            check_kind(c)
            check_operator(c)
        except ValueError as e:
            problems.append(f"common_checks: {e}")
    return problems


# --------------------------------------------------------------------------- operators

def _s(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    return str(v)


def expand(operand, ctx: dict) -> list:
    """"$targets" / "$outsider" / "$intra" inside a list operand become their values."""
    items = operand if isinstance(operand, list) else [operand]
    out = []
    for item in items:
        if isinstance(item, str) and item.startswith("$") and item[1:] in ctx:
            val = ctx[item[1:]]
            out.extend(val if isinstance(val, list) else [val])
        else:
            out.append(item)
    return out


def evaluate(check: dict, values: list, ctx: dict | None = None) -> tuple[bool, str]:
    ctx = ctx or {}
    op = check_operator(check)
    got = {_s(v) for v in values}
    if op in SET_OPS:
        want = {_s(v) for v in expand(check[op], ctx)}
        if op == "equals":
            return got == want, f"missing={sorted(want - got)} extra={sorted(got - want)}"
        if op == "superset":
            return want <= got, f"missing={sorted(want - got)}"
        if op == "subset":
            return got <= want, f"outside={sorted(got - want)}"
        return not (got & want), f"present={sorted(got & want)}"
    if op == "true":
        return values == [True], f"rows={values[:5]}"
    if op == "count":
        return len(values) == int(check[op]), f"rows={len(values)} sample={values[:5]}"
    if op == "min":
        return len(values) >= int(check[op]), f"rows={len(values)} sample={values[:5]}"
    if op == "max":
        return len(values) <= int(check[op]), f"rows={len(values)} sample={values[:5]}"
    if op == "contains":
        text = "\n".join(_s(v) for v in values).lower()
        missing = [s for s in expand(check[op], ctx) if str(s).lower() not in text]
        return not missing, f"missing={missing} in {text[:200]!r}"
    return True, f"values={sorted(got)[:40]}" + (f" (+{len(got) - 40})" if len(got) > 40 else "")


# --------------------------------------------------------------------------- evidence readers

def match_where(row: dict, where: dict | None) -> bool:
    for key, want in (where or {}).items():
        have = row.get(key)
        empty = have in (None, "", [])
        if want == "*":
            if empty:
                return False
        elif want is None:
            if not empty:
                return False
        elif isinstance(want, dict) and "not" in want:
            if _s(have) == _s(want["not"]):
                return False
        elif isinstance(want, list):
            if _s(have) not in {_s(w) for w in want}:
                return False
        elif _s(have) != _s(want):
            return False
    return True


def project(rows: list[dict], check: dict) -> list:
    rows = [r for r in rows if match_where(r, check.get("where"))]
    field = check.get("field")
    return [r.get(field) for r in rows] if field else rows


def walk(node, path) -> list:
    """Values at a path of nested dicts/lists. A path is a list, or a dotted
    string (use the list form when a key holds dots, e.g. a hostname)."""
    parts = path if isinstance(path, list) else str(path).split(".")
    nodes = [node]
    for part in parts:
        nxt = []
        for n in nodes:
            if part == "*":
                nxt.extend(n.values() if isinstance(n, dict) else n if isinstance(n, list) else [])
            elif isinstance(n, dict) and part in n:
                nxt.append(n[part])
            elif isinstance(n, list) and str(part).isdigit() and int(part) < len(n):
                nxt.append(n[int(part)])
        nodes = nxt
    return nodes


def recon_values(data: dict, check: dict) -> list:
    out = []
    for node in walk(data, check["recon_json"]):
        if check.get("pairs") and isinstance(node, dict):
            out.extend(f"{k}={(v or {}).get(check['pairs']) if isinstance(v, dict) else v}" for k, v in node.items())
        elif isinstance(node, dict):
            out.extend(node.keys())
        elif isinstance(node, list):
            out.extend(node)
        else:
            out.append(node)
    return out


class Evidence:
    """One step's frozen evidence (generated/runs/<row>-<stamp>/<label>/)."""

    def __init__(self, step_dir: Path, mcp: iphn_lab.Mcp | None = None):
        self.dir = step_dir
        self.meta = self._json("meta.json") or {}
        self.mcp = mcp

    def _json(self, name: str):
        p = self.dir / name
        return json.loads(p.read_text()) if p.is_file() else None

    def window(self) -> tuple[float | None, float | None]:
        return self.meta.get("t_start"), self.meta.get("t_end")

    def hits(self, which: str) -> list[dict]:
        folder = self.dir / "hits"
        files = sorted(folder.glob("*.jsonl")) if which == "all" else [folder / f"{which}.jsonl"]
        out = []
        for f in files:
            out.extend(iphn_lab.read_hits(f))
        return out

    def packets(self) -> list[dict]:
        p = self.dir / "outsider.pcap"
        if not p.is_file():
            raise FileNotFoundError(f"{p} missing: the step collected no capture")
        t0, t1 = self.window()
        return [x for x in iphn_lab.parse_pcap(p.read_bytes())
                if (t0 is None or x["ts"] >= t0) and (t1 is None or x["ts"] <= t1)]

    def dns(self) -> list[dict]:
        p = self.dir / "dns.log"
        if not p.is_file():
            raise FileNotFoundError(f"{p} missing: the step collected no DNS log")
        return iphn_lab.parse_dns_log(p.read_text(errors="replace"))

    def values(self, check: dict) -> list:
        kind = check_kind(check)
        if kind == "cypher":
            if self.mcp is None:
                raise RuntimeError("a cypher check needs the MCP server")
            pid = self.meta.get("project_id")
            if not pid:
                raise RuntimeError("the step has no project id")
            return self.mcp.cypher(pid, check["cypher"])
        if kind == "recon_json":
            p = self.dir / "recon.json"
            if not p.is_file():
                raise FileNotFoundError(f"{p} missing")
            return recon_values(json.loads(p.read_text()), check)
        if kind == "hits":
            return project(self.hits(str(check["hits"])), check)
        if kind == "pcap":
            where = check.get("where")
            rows = self.packets()
            if not where or "dst" not in where:
                rows = [r for r in rows if r.get("dst") == iphn_lab.OUTSIDER]
            return project(rows, check)
        if kind == "dnslog":
            return project(self.dns(), check)
        if kind == "scan_log":
            p = self.dir / "recon.log"
            lines = p.read_text(errors="replace").splitlines() if p.is_file() else []
            rx = re.compile(check["scan_log"])
            return [ln for ln in lines if rx.search(ln)]
        if kind == "run":
            return [self.meta.get(check["run"])]
        if kind == "result":
            res = self._json("result.json")
            if res is None:
                raise FileNotFoundError(f"{self.dir / 'result.json'} missing")
            got = walk(res, check["result"])
            return got[0] if len(got) == 1 and isinstance(got[0], list) else got
        return []


def context(meta: dict) -> dict:
    state = iphn_lab.GEN / "lab.json"
    lab = json.loads(state.read_text()) if state.is_file() else {}
    return {"targets": list(meta.get("targets") or []), "outsider": [iphn_lab.OUTSIDER],
            "intra": [lab["intra_ip"]] if lab.get("intra_ip") else []}


def run_checks(checks: list[dict], ev: Evidence) -> list[dict]:
    ctx = context(ev.meta)
    results = []
    for c in checks:
        kind = check_kind(c)
        if kind == "manual":
            results.append({"id": c["id"], "status": "MANUAL", "detail": c["manual"]})
            continue
        try:
            values = ev.values(c)
            ok, detail = evaluate(c, values, ctx)
            status = "PASS" if ok else "FAIL"
        except Exception as e:  # one broken check must not hide the others
            status, detail = "FAIL", f"{type(e).__name__}: {str(e)[:300]}"
        if check_operator(c) == "record":
            status = "RECORD" if status == "PASS" else status
        results.append({"id": c["id"], "status": status, "detail": detail, "kind": kind,
                        "note": c.get("note", "")})
    return results


def print_results(row_id: str, label: str, results: list[dict]) -> int:
    failed = 0
    for r in results:
        failed += r["status"] == "FAIL"
        sym = {"PASS": "+", "RECORD": "*", "MANUAL": "-"}.get(r["status"], "!")
        tail = "" if r["status"] == "PASS" else f"  {r['detail']}"
        print(f"[{sym}][Validate] {r['status']:6s} {row_id}.{label}.{r['id']}{tail}", flush=True)
    return failed


def validate_step(spec: dict, row_id: str, label: str, kind: str, step_dir: Path,
                  mcp: iphn_lab.Mcp | None) -> list[dict]:
    results = run_checks(checks_for(spec, row_id, label, kind), Evidence(step_dir, mcp))
    (step_dir / "checks.json").write_text(json.dumps(results, indent=1, default=str))
    print_results(row_id, label, results)
    return results


# --------------------------------------------------------------------------- RESULTS.md

def latest_runs(runs: Path = iphn_lab.RUNS) -> dict[str, Path]:
    latest: dict[str, Path] = {}
    for d in sorted(runs.glob("E*-*")) if runs.is_dir() else []:
        rid = d.name.split("-", 1)[0]
        if (d / "row.json").is_file():
            latest[rid] = d
    return latest


def write_report(out: Path, spec: dict, roots: dict[str, Path]) -> int:
    lines = ["# IP-hostnames lab: results", "",
             f"Generated {time.strftime('%Y-%m-%d %H:%M:%S %Z')} by validate_ip_hostnames.py from "
             "generated/runs/ (latest run of each row). Lab range 192.88.98.0/24 and reserved names only.", "",
             "| Row | Title | Outcome | PASS | FAIL | Run |", "|---|---|---|---|---|---|"]
    body, failed = [], 0
    for rid in ROW_IDS:
        row = spec["rows"].get(rid, {})
        root = roots.get(rid)
        if not root:
            lines.append(f"| {rid} | {row.get('title', '')} | not run | | | |")
            continue
        info = json.loads((root / "row.json").read_text())
        counts = {"PASS": 0, "FAIL": 0}
        body += ["", f"## {rid}: {row.get('title', '')}", "",
                 f"- outcome: **{info.get('outcome')}**" + (f" ({info.get('reason')})" if info.get("reason") else ""),
                 f"- run folder: `{root.relative_to(iphn_lab.HERE)}`",
                 f"- projects: {', '.join(f'{k}={v}' for k, v in (info.get('projects') or {}).items()) or 'none'}"]
        for step in info.get("steps") or []:
            sdir = root / step["label"]
            res = json.loads((sdir / "checks.json").read_text()) if (sdir / "checks.json").is_file() else []
            meta = json.loads((sdir / "meta.json").read_text()) if (sdir / "meta.json").is_file() else {}
            body += ["", f"### {step['label']} ({step['kind']}, status {meta.get('status', step.get('status'))})", ""]
            for r in res:
                counts[r["status"]] = counts.get(r["status"], 0) + 1
                body.append(f"- {r['status']} `{r['id']}`" + ("" if r["status"] == "PASS" else f": {r['detail']}"))
        failed += counts["FAIL"]
        lines.append(f"| {rid} | {row.get('title', '')} | {info.get('outcome')} | {counts['PASS']} | "
                     f"{counts['FAIL']} | `{root.name}` |")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines + body) + "\n")
    print(f"[+][Validate] wrote {out}")
    return failed


# --------------------------------------------------------------------------- self-test

def _pcap_bytes(packets: list[tuple[float, bytes]]) -> bytes:
    out = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts, frame in packets:
        out += struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)) + frame
    return out


def _eth_ipv4_tcp(src: str, dst: str, sport: int, dport: int, flags: int) -> bytes:
    ip = bytes([0x45, 0, 0, 40, 0, 0, 0, 0, 64, 6, 0, 0]) + bytes(map(int, src.split("."))) + \
        bytes(map(int, dst.split(".")))
    tcp = struct.pack(">HHIIBBHHH", sport, dport, 0, 0, 0x50, flags, 1024, 0, 0)
    return b"\x02" * 6 + b"\x04" * 6 + b"\x08\x00" + ip + tcp


def _arp() -> bytes:
    return b"\xff" * 6 + b"\x04" * 6 + b"\x08\x06" + b"\x00" * 28


SELF_YAML = """
common_checks:
  - {id: c1, run: status, equals: [completed]}
rows:
  E0:
    title: canned
    common: true
    sequence: [{run: a}, {zone: {moved: 99}, label: z}, {run: b}]
    checks:
      - {id: x, step: a, cypher: "RETURN 1 AS v", count: 1}
      - {id: y, pcap: outsider, min: 1}
"""


def self_test() -> int:
    failures = []

    def expect(name: str, cond: bool, detail: str = "") -> None:
        print(f"[{'+' if cond else '!'}][SelfTest] {'PASS' if cond else 'FAIL'} {name}" + ("" if cond else f"  {detail}"))
        if not cond:
            failures.append(name)

    ctx = {"targets": ["192.88.98.10", "192.88.98.11"], "outsider": ["192.88.98.99"], "intra": []}
    cases = [
        ({"equals": ["a", "b"]}, ["b", "a", "a"], True), ({"equals": ["a"]}, ["a", "b"], False),
        ({"superset": ["a"]}, ["a", "b"], True), ({"superset": ["c"]}, ["a", "b"], False),
        ({"subset": ["$targets"]}, ["192.88.98.10"], True), ({"subset": "$targets"}, ["192.88.98.99"], False),
        ({"disjoint": ["$outsider"]}, ["192.88.98.10"], True), ({"disjoint": ["$outsider"]}, ["192.88.98.99"], False),
        ({"true": True}, [True], True), ({"true": True}, [False], False), ({"true": True}, [True, True], False),
        ({"count": 0}, [], True), ({"count": 2}, [1], False),
        ({"min": 1}, [1, 2], True), ({"min": 1}, [], False), ({"max": 1}, [1], True), ({"max": 1}, [1, 2], False),
        ({"contains": ["Authorization"]}, ["refused: authorization_required"], True),
        ({"contains": ["busy"]}, ["ok"], False),
        ({"record": True}, ["x"], True), ({"equals": [None]}, [None], True), ({"equals": [True]}, [True], True),
    ]
    for i, (op, values, want) in enumerate(cases):
        check = {"id": f"op{i}", "run": "status", **op}
        ok, detail = evaluate(check, values, ctx)
        expect(f"operator {list(op)[0]} #{i} -> {want}", ok == want, detail)
    try:
        evaluate({"id": "bad", "run": "status", "equals": [1], "count": 1}, [], ctx)
        expect("two operators are refused", False)
    except ValueError:
        expect("two operators are refused", True)

    spec = parse_spec(SELF_YAML)
    expect("canned YAML parses", "E0" in spec["rows"])
    expect("labels from the sequence", [step_label(s) for s in sequence(spec["rows"]["E0"])] == ["a", "z", "b"])
    a = [c["id"] for c in checks_for(spec, "E0", "a", "run")]
    b = [c["id"] for c in checks_for(spec, "E0", "b", "run")]
    z = [c["id"] for c in checks_for(spec, "E0", "z", "zone")]
    expect("checks route to their step, common to runs only", a == ["x", "common:c1"] and
           b == ["y", "common:c1"] and z == [], f"a={a} b={b} z={z}")
    probs = spec_problems(spec)
    expect("a partial spec reports the missing rows", any("E25" in p for p in probs), str(probs[:3]))
    bad = parse_spec("rows:\n  E0: {title: t, checks: [{id: q, cypher: x, hits: all, count: 1}]}\n")
    expect("a check with two kinds is reported", any("exactly one kind" in p for p in spec_problems(bad)))
    yaml11 = parse_spec("rows:\n  E0: {title: t, sequence: [{run: a, on: m2}]}\n")
    expect("an unquoted on: key (a YAML 1.1 boolean) is reported",
           any("boolean key" in p for p in spec_problems(yaml11)))

    real = load_expected()
    probs = spec_problems(real)
    expect("expected_results.yaml: every row E0-E25, every check well formed", not probs, "; ".join(probs[:5]))
    e0 = [c["id"] for c in checks_for(real, "E0", "main", "run")]
    expect("E0 checks the outsider RECEIVES packets", "outsider_receives_packets" in e0, str(e0))

    data = _pcap_bytes([(100.25, _eth_ipv4_tcp("192.88.98.1", "192.88.98.99", 40000, 443, 0x02)),
                        (101.5, _arp()),
                        (102.0, _eth_ipv4_tcp("192.88.98.250", "192.88.98.99", 40001, 80, 0x18))])
    pk = iphn_lab.parse_pcap(data)
    expect("pcap: three frames", len(pk) == 3, str(pk))
    expect("pcap: SYN from the scanner host to 443", pk[0]["src"] == "192.88.98.1" and pk[0]["dport"] == 443
           and pk[0]["flags"] == "S" and abs(pk[0]["ts"] - 100.25) < 1e-3, str(pk[0]))
    expect("pcap: ARP is not IP", pk[1]["proto"] == "other" and pk[1]["dst"] is None)
    expect("pcap: where/field", project(pk, {"where": {"src": "192.88.98.1"}, "field": "dport"}) == [443])

    log = ('2026-11-10T19:31:36.854874906Z [INFO] 192.88.98.1:60680 - 58372 "PTR IN 10.98.88.192.in-addr.arpa. '
           'udp 66 false 1232" NOERROR qr,aa,rd 144 0.000141581s\n'
           '[INFO] 192.88.98.1:39390 - 29767 "A IN App.Example-A.test. udp 66 false 1232" NOERROR qr,aa,rd 159 0.0001s\n'
           '[INFO] plugin/reload: Running configuration SHA512 = abc\n')
    q = iphn_lab.parse_dns_log(log)
    expect("dnslog: two queries, reload line ignored", len(q) == 2, str(q))
    expect("dnslog: PTR address and lower-cased name",
           q[0]["ptr_ip"] == "192.88.98.10" and q[1]["name"] == "app.example-a.test", str(q))
    expect("dnslog: where qtype PTR", len(project(q, {"where": {"qtype": "PTR"}})) == 1)

    hits = [iphn_lab.normalise_hit(h) for h in (
        {"ts": 1.0, "host": "App.Example-A.test:443", "sni": "app.example-a.test", "status": 200},
        {"ts": 2.0, "host": "192.88.98.10", "sni": "", "status": 200},
        {"ts": 3.0, "host": "", "sni": "", "status": 400})]
    expect("hits: host_name strips the port", hits[0]["host_name"] == "app.example-a.test")
    expect("hits: empty SNI is null", hits[1]["sni"] is None)
    expect("hits: where sni '*'", len(project(hits, {"where": {"sni": "*"}})) == 1)
    expect("hits: where sni null", len(project(hits, {"where": {"sni": None}})) == 2)
    expect("hits: where {not: 400}", len(project(hits, {"where": {"status": {"not": 400}}})) == 2)
    expect("hits: where any-of", len(project(hits, {"where": {"status": [400, 500]}})) == 1)

    doc = {"ip_hostnames": {"mode": "record_filter", "candidates": {
        "app.example-a.test": {"reason": "scanned", "ips_seen": ["192.88.98.10"]},
        "split.example-a.test": {"reason": "resolves_outside_targets", "ips_seen": ["192.88.98.13"]}}},
        "dns": {"subdomains": {"192-88-98-10": {"is_mock": True}}}}
    expect("recon_json: dotted path to a scalar", recon_values(doc, {"recon_json": "ip_hostnames.mode"}) == ["record_filter"])
    expect("recon_json: dict gives its keys", recon_values(doc, {"recon_json": "dns.subdomains"}) == ["192-88-98-10"])
    expect("recon_json: pairs", sorted(recon_values(doc, {"recon_json": "ip_hostnames.candidates", "pairs": "reason"}))
           == ["app.example-a.test=scanned", "split.example-a.test=resolves_outside_targets"])
    expect("recon_json: list path with a dotted key and *",
           recon_values(doc, {"recon_json": ["ip_hostnames", "candidates", "app.example-a.test", "ips_seen"]})
           == ["192.88.98.10"] and len(recon_values(doc, {"recon_json": "ip_hostnames.candidates.*.reason"})) == 2)
    expect("expand: $targets inside a list", expand(["$targets", "x"], ctx) == ["192.88.98.10", "192.88.98.11", "x"])

    print(f"\n[{'+' if not failures else '!'}][SelfTest] {'all passed' if not failures else f'{len(failures)} failed'}")
    return 1 if failures else 0


# --------------------------------------------------------------------------- CLI

def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--self-test", action="store_true")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--row")
    ap.add_argument("--run-root", type=Path)
    ap.add_argument("--report", action="store_true")
    ap.add_argument("--out", type=Path, default=iphn_lab.GEN / "RESULTS.md")
    ap.add_argument("--token-var")
    a = ap.parse_args()

    if a.self_test:
        return self_test()
    spec = load_expected()
    problems = spec_problems(spec)
    if problems:
        for p in problems:
            print(f"[!][Validate] {p}")
        return 1
    if a.list:
        for rid in ROW_IDS:
            row = spec["rows"][rid]
            need = ",".join(needs_steps(row)) or "-"
            print(f"{rid:4s} [{row.get('kind', 'full'):10s}] needs {need:8s} {row['title']}")
            if row.get("kind") == "external":
                continue
            for st in sequence(row):
                label, kind = step_label(st), action_of(st)
                print(f"       {kind:12s} {label:18s} {len(checks_for(spec, rid, label, kind))} check(s)")
        return 0
    if a.report:
        return 1 if write_report(a.out, spec, latest_runs()) else 0
    if not (a.row and a.run_root):
        ap.error("--row and --run-root (or --self-test, --list, --report)")
    info = json.loads((a.run_root / "row.json").read_text())
    mcp = iphn_lab.Mcp(a.token_var)
    failed = 0
    for step in info.get("steps") or []:
        res = validate_step(spec, a.row, step["label"], step["kind"], a.run_root / step["label"], mcp)
        failed += sum(r["status"] == "FAIL" for r in res)
    write_report(a.out, spec, {**latest_runs(), a.row: a.run_root})
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
