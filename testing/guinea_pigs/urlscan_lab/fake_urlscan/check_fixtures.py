#!/usr/bin/env python3
"""Validate every answer the fixtures can produce against urlscan_search.schema.json.

    python3 -I fake_urlscan/check_fixtures.py [--fixtures generated/fixtures/visits.json]

Renders each visit, and every search RedAmon sends (the main search with its
pages, keyed and not, the redirect search, the hash and filename searches) plus
the error answers, through server.py's own code, then checks the schema and
the §10.1 rules the schema cannot express (no lab-only key leaks, newest first,
sort = [epoch ms, uuid], has_more only above 10,000, 100 a page without a key).
up.sh refuses to start the lab when this fails. Exit 1 on any problem.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

HERE = Path(__file__).resolve().parent
LAB = HERE.parent


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


server = _load("uslab_fake_urlscan", HERE / "server.py")
schema_check = _load("uslab_schema_check", HERE / "schema_check.py")

LAB_ONLY = {"age_days", "touched_domains", "files", "lab_id", "group", "lab_expect"}


def _nulls(value, path="$") -> list[str]:
    if value is None:
        return [path]
    if isinstance(value, dict):
        return [p for k, v in value.items() if k != "_score" for p in _nulls(v, f"{path}.{k}")]
    if isinstance(value, list):
        return [p for i, v in enumerate(value) for p in _nulls(v, f"{path}[{i}]")]
    return []


def _body_rules(label: str, body: dict, keyed: bool) -> list[str]:
    out = []
    results = body.get("results", [])
    keys = [tuple(r["sort"]) for r in results]
    if keys != sorted(keys, reverse=True):
        out.append(f"{label}: results are not newest first")
    for r in results:
        leaked = LAB_ONLY & set(r)
        if leaked:
            out.append(f"{label}: lab-only keys returned {sorted(leaked)}")
        if r["_id"] != r["task"]["uuid"] or r["sort"][1] != r["task"]["uuid"]:
            out.append(f"{label}: _id/sort do not carry task.uuid")
        t = datetime.strptime(r["task"]["time"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
        if int(t.timestamp() * 1000) != r["sort"][0]:
            out.append(f"{label}: sort[0] is not task.time in epoch ms")
        for p in _nulls(r):
            out.append(f"{label}: {p} is null (optional fields must be absent)")
        if "verdicts" in r and not keyed:
            out.append(f"{label}: verdicts returned without a key")
    if not keyed and len(results) > server.ANON_PAGE_CAP:
        out.append(f"{label}: {len(results)} results without a key (cap {server.ANON_PAGE_CAP})")
    if body.get("has_more") and body.get("total", 0) < server.TOTAL_CAP:
        out.append(f"{label}: has_more true below the {server.TOTAL_CAP} cap")
    if keyed == ("search_date_limit_days" in body):
        out.append(f"{label}: search_date_limit_days {'present with' if keyed else 'missing without'} a key")
    return out


def _page_through(state, q: str, keyed: bool, size: int) -> tuple[list[dict], list[str]]:
    """Every page of one search, the way RedAmon pages: search_after until a short page."""
    bodies, problems, after = [], [], None
    for _ in range(200):
        qs = f"q={q}&size={size}" + (f"&search_after={after}" if after else "")
        status, _headers, body = state.handle_search(qs, "lab-key" if keyed else None, "check")
        if status != 200:
            problems.append(f"{q!r}: HTTP {status}")
            break
        bodies.append(body)
        if len(body["results"]) < min(size, server.KEYED_PAGE_CAP if keyed else server.ANON_PAGE_CAP):
            break
        last = body["results"][-1]["sort"]
        after = f"{last[0]},{last[1]}"
    return bodies, problems


def check(visits: list[dict], meta: dict | None = None) -> list[str]:
    """Problems found; [] means the fixtures render in urlscan's format."""
    from urllib.parse import quote
    schema = schema_check.load_schema()
    problems: list[str] = []
    lab_start = datetime.now(timezone.utc)

    for v in visits:
        for keyed in (False, True):
            body = {"results": [server.render(v, lab_start, keyed, "http://192.88.97.30")],
                    "total": 1, "took": 0, "has_more": False}
            if not keyed:
                body["search_date_limit_days"] = 30
            label = f"visit {v.get('lab_id')} ({'keyed' if keyed else 'anonymous'})"
            problems += [f"{label}: {e}" for e in schema_check.check_search(body, schema)]
            problems += _body_rules(label, body, keyed)

    state = server.LabState(visits, lab_start=lab_start, clock=lambda: 0.0)
    domain = (meta or {}).get("domain", "uslab.test")
    queries = [f"page.domain:{domain}",
               f"task.apexDomain:{domain} AND NOT page.apexDomain:{domain}",
               f"domain:{domain}", "page.redirected:off-domain", "task.tags:phishing",
               f"(page.domain:{domain} OR task.domain:{domain}) AND NOT task.tags:phishing"]
    for bundle in ((meta or {}).get("bundles") or {}).values():
        queries += [f"hash:{bundle['sha256']}", f'filename:"{bundle["name"]}"']
    for q in queries:
        for keyed in (False, True):
            state.reset()
            bodies, errs = _page_through(state, quote(q), keyed, 100 if not keyed else 10000)
            problems += errs
            for i, body in enumerate(bodies):
                label = f"{q!r} page {i + 1} ({'keyed' if keyed else 'anonymous'})"
                problems += [f"{label}: {e}" for e in schema_check.check_search(body, schema)]
                problems += _body_rules(label, body, keyed)

    expected = (meta or {}).get("anonymous_visible")
    if expected is not None:
        state.reset()
        bodies, _ = _page_through(state, quote(f"page.domain:{domain}"), False, 100)
        sizes = [len(b["results"]) for b in bodies]
        if sum(sizes) != expected or bodies[0]["total"] != expected:
            problems.append(f"main search without a key returned {sizes} (total "
                            f"{bodies[0]['total'] if bodies else '?'}), expected {expected} visits")

    for q, keyed, want in (("nosuchfield:x", False, 400), (f"page.domain:*.{domain}", False, 403),
                           ("page.domain:/uslab.*/", False, 403), ("", False, 400)):
        state.reset()
        status, _h, body = state.handle_search(f"q={quote(q)}", "lab-key" if keyed else None, "check")
        if status != want:
            problems.append(f"error case {q!r}: HTTP {status}, expected {want}")
        problems += [f"error {q!r}: {e}" for e in schema_check.check_error(body, schema)]
    state.reset()
    state.add_fail({"query_regex": ".", "status": 429, "times": 1})
    status, headers, body = state.handle_search(f"q={quote('page.domain:' + domain)}", None, "check")
    if status != 429 or "Retry-After" not in headers:
        problems.append(f"forced 429: HTTP {status}, Retry-After {'present' if 'Retry-After' in headers else 'missing'}")
    problems += [f"error 429: {e}" for e in schema_check.check_error(body, schema)]
    return problems


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--fixtures", type=Path, default=LAB / "generated" / "fixtures" / "visits.json")
    ap.add_argument("--meta", type=Path, default=LAB / "generated" / "lab.json")
    a = ap.parse_args()
    if not a.fixtures.is_file():
        print(f"[!] {a.fixtures} missing: run gen_lab.py first")
        return 1
    visits = server.load_visits(str(a.fixtures))
    meta = json.loads(a.meta.read_text()) if a.meta.is_file() else None
    problems = check(visits, meta)
    for p in problems[:50]:
        print(f"[!] {p}")
    if len(problems) > 50:
        print(f"[!] ... and {len(problems) - 50} more")
    print(f"[{'+' if not problems else '!'}] {len(visits)} visits, "
          f"{'every answer matches the schema' if not problems else f'{len(problems)} problem(s)'}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
