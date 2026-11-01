#!/usr/bin/env python3
"""Check a lab project's js_recon graph against expected.json. PASS/FAIL per row.

    python3 validate_js_secrets.py <projectId> [--phase e0|p0|p1|p2] [--trufflehog on|off]
                                   [--real-expected <expected_real.json>] [--strict-extra]

  --phase e0   the code before Phase 0: each row's `regex_today`
          p0   after Phase 0: `regex`
          p1   after Phase 1: `regex`, plus the TruffleHog column when --trufflehog on
          p2   after Phase 2: `regex_p2` where a row has one, else `regex`
  --trufflehog off (p1/p2): no node may carry any TruffleHog trace.

Read through cypher-shell inside redamon-neo4j (muted nodes included, the
password stays in the container). Values are compared as sha256[:12], computed
IN the database (apoc.util.sha256): no matched text leaves Neo4j, and nothing
here prints one. Exit 1 on any FAIL.

A row matches the regex node on its file whose matched_text hashes to the row's
match_sha12 (the text the rule matches) or value_sha12. .12's hashes depend on
the canary's address and come from generated/expected_runtime.json. Row
`trufflehog`: "TBD" (skipped), null (TruffleHog must not report it), or
{"detector": "<DetectorName>", "secret_type": "<js_recon name>", "severity": ...,
"public_client_key": bool, "raw_sha12": "<sha12 of Raw, default value_sha12>",
"decoded": bool}.
"""
import argparse
import collections
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from snapshot import check_pid, cypher_rows  # noqa: E402

EXPECTED = os.path.join(HERE, "expected.json")
RUNTIME = os.path.join(HERE, "generated", "expected_runtime.json")
SEV = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}
QUIET_HOSTS = ("192.88.96.11", "192.88.96.14")

SECRETS = """
MATCH (s:Secret {project_id: $pid}) WHERE s.source = 'js_recon'
OPTIONAL MATCH (j:JsReconFinding {finding_type: 'js_file'})-[:HAS_SECRET]->(s)
WITH s, count(j) AS parents
RETURN apoc.text.base64Encode(apoc.convert.toJson({
  id: s.id, secret_type: s.secret_type, severity: s.severity, public_client_key: s.public_client_key,
  source_url: s.source_url, base_url: s.base_url, key_type: s.key_type, confidence: s.confidence,
  detection_method: coalesce(s.detection_method, 'regex'), validation_status: s.validation_status,
  validation_info: s.validation_info, line_number: s.line_number, alternate_names: s.alternate_names,
  muted: s.muted, mt12: substring(apoc.util.sha256([coalesce(s.matched_text, '')]), 0, 12),
  context_empty: coalesce(s.context, '') = '', parents: parents})) AS b
"""

# A credential's matched text inside another Secret's context is a leak. Info and
# infrastructure hits (an email, a private IP) are readable in a context by design.
CONTEXT_LEAKS = """
MATCH (a:Secret {project_id: $pid}), (b:Secret {project_id: $pid})
WHERE a.source = 'js_recon' AND b.source = 'js_recon'
  AND NOT coalesce(a.key_type, '') IN ['info', 'infrastructure']
  AND size(coalesce(a.matched_text, '')) >= 8 AND coalesce(b.context, '') CONTAINS a.matched_text
RETURN apoc.text.base64Encode(apoc.convert.toJson({holder: b.id, holder_type: b.secret_type,
  value_of: a.id, value_type: a.secret_type})) AS b
"""

results = []


def check(case, ok, detail, level=None):
    results.append((level or ("PASS" if ok else "FAIL"), case, detail))


def load_rows():
    with open(EXPECTED, encoding="utf-8") as fh:
        rows = json.load(fh)["rows"]
    runtime = {}
    if os.path.exists(RUNTIME):
        with open(RUNTIME, encoding="utf-8") as fh:
            runtime = {r["label"]: r for r in json.load(fh).get("rows", [])}
    for row in rows:
        if row["value_sha12"] == "runtime":
            live = runtime.get(row["label"])
            row["unresolved"] = live is None
            if live:
                row["value_sha12"], row["match_sha12"] = live["value_sha12"], live["match_sha12"]
    return rows


def url_of(row):
    return f"upload://{row['file']}" if row["host"] == "upload" else f"http://{row['host']}{row['file']}"


def is_trufflehog(node):
    return node["detection_method"] == "trufflehog"


def th_alt(node):
    return [a for a in (node.get("alternate_names") or []) if str(a).startswith("TruffleHog:")]


def validation(node):
    try:
        return json.loads(node.get("validation_info") or "{}") or {}
    except ValueError:
        return {}


def regex_rows(rows, nodes, phase):
    key = {"e0": "regex_today", "p0": "regex", "p1": "regex"}.get(phase)
    by_url = collections.defaultdict(list)
    for n in nodes:
        by_url[n["source_url"]].append(n)
    claimed = set()
    uploaded = any(u.startswith("upload://") for u in by_url)
    for row in rows:
        exp = row.get("regex_p2", row["regex"]) if phase == "p2" else row[key]
        if row.get("unresolved"):
            check(row["label"], False, "no runtime hash: run gen_lab.py with the canary up", "SKIP")
            continue
        if row["host"] == "upload" and not uploaded:
            check(row["label"], False, "no upload in this run (only E4's partial recon uploads)", "SKIP")
            continue
        hashes = {row["match_sha12"], row["value_sha12"]}
        cands = [n for n in by_url.get(url_of(row), []) if not is_trufflehog(n) and n["mt12"] in hashes]
        if exp is None:
            claimed.update(n["id"] for n in cands)
            check(row["label"], not cands, "no regex finding" if not cands else
                  f"expected none, found {sorted((n['secret_type'], n['severity']) for n in cands)}")
            continue
        hit = [n for n in cands if n["secret_type"] == exp["secret_type"]]
        claimed.update(n["id"] for n in hit)
        if not hit:
            check(row["label"], False, f"expected {exp['secret_type']} [{exp['severity']}], found "
                                       f"{sorted((n['secret_type'], n['severity']) for n in cands) or 'nothing'}")
            continue
        node, problems = hit[0], []
        if len(hit) > 1:
            problems.append(f"{len(hit)} nodes")
        if node["severity"] != exp["severity"]:
            problems.append(f"severity {node['severity']} (expected {exp['severity']})")
        if bool(node["public_client_key"]) != exp["public_client_key"]:
            problems.append(f"public_client_key {node['public_client_key']}")
        # alternate_names reaches the graph in Phase 1 (step 1.8), not before.
        if phase in ("p1", "p2"):
            missing = [a for a in exp.get("alternate_names_include", [])
                       if a not in (node.get("alternate_names") or [])]
            if missing:
                problems.append(f"alternate_names lacks {missing}")
        check(row["label"], not problems, f"{exp['secret_type']} [{exp['severity']}]"
              + (f"{' public' if exp['public_client_key'] else ''}" if not problems else ": " + "; ".join(problems)))
    return claimed


def trufflehog_rows(rows, nodes, claimed):
    by_url = collections.defaultdict(list)
    for n in nodes:
        by_url[n["source_url"]].append(n)
    tbd = [r["label"] for r in rows if r.get("trufflehog") == "TBD"]
    if tbd:
        check("trufflehog-column", False, f"{len(tbd)} rows still TBD (fill expected.json in plan step 1.3)", "SKIP")
    uploaded = any(u.startswith("upload://") for u in by_url)
    for row in rows:
        th = row.get("trufflehog")
        if th == "TBD" or row.get("unresolved") or (row["host"] == "upload" and not uploaded):
            continue
        case = f"{row['label']} (TruffleHog)"
        here = by_url.get(url_of(row), [])
        raw = (th or {}).get("raw_sha12") or row["value_sha12"]
        only = [n for n in here if is_trufflehog(n) and n["mt12"] in (raw, row["value_sha12"])]
        merged = [n for n in here if not is_trufflehog(n) and n["mt12"] in (row["match_sha12"], row["value_sha12"])
                  and any(a == f"TruffleHog:{(th or {}).get('detector')}" for a in th_alt(n))]
        if th is None:
            check(case, not only, "not reported" if not only else f"reported as {[n['secret_type'] for n in only]}")
            continue
        if row["regex"] is not None and merged:
            check(case, True, f"merged into the regex node (TruffleHog:{th['detector']})")
            continue
        if not only:
            check(case, False, f"no TruffleHog node for {th['detector']}"
                               + (" and no merged regex node" if row["regex"] is not None else ""))
            continue
        node, problems = only[0], []
        if len(only) > 1:
            problems.append(f"{len(only)} nodes")
        for field in ("secret_type", "severity", "public_client_key"):
            if field in th and node.get(field) != th[field]:
                problems.append(f"{field} {node.get(field)!r} (expected {th[field]!r})")
        if node["parents"] < 1:
            problems.append("no HAS_SECRET parent")
        if th.get("decoded"):
            if not node["context_empty"]:
                problems.append("a decoded hit must have an empty context")
        elif not isinstance(node.get("line_number"), int):
            problems.append("no line_number")
        check(case, not problems, f"TruffleHog-only {node['secret_type']} [{node['severity']}]"
              if not problems else "; ".join(problems))


def global_checks(nodes, phase, trufflehog, strict_extra, claimed, pid):
    leaks = cypher_rows(CONTEXT_LEAKS, pid)
    check("no-raw-in-context", not leaks, "no Secret context holds another's matched text" if not leaks else
          f"{len(leaks)} contexts hold a matched value: "
          f"{sorted({(l['holder_type'], l['value_type']) for l in leaks})}")

    dupes = collections.Counter((n["secret_type"], n["source_url"], n["mt12"]) for n in nodes)
    dupes = {k: v for k, v in dupes.items() if v > 1}
    check("no-duplicates", not dupes, "one node per (type, file, value)" if not dupes else
          f"{len(dupes)} duplicated: {sorted((t, c) for (t, _, _), c in dupes.items())}")

    for host in QUIET_HOSTS:
        loud = [n for n in nodes if n["source_url"].startswith(f"http://{host}/") and SEV.get(n["severity"], 0) >= 3]
        detail = (f"{len(loud)} Secret(s) >= medium: "
                  f"{sorted(collections.Counter(n['secret_type'] for n in loud).items())}" if loud else
                  "no Secret >= medium")
        # Today's code is expected to fire on library code; that is the census, not a failure.
        check(f"quiet-{host}", not loud, detail, "INFO" if phase == "e0" and loud else None)
    clean = [n for n in nodes if n["source_url"].startswith("http://192.88.96.14/")]
    if clean:
        check("clean-control-empty", True, f"{len(clean)} low/info Secret(s) on .14", "WARN")

    extra = [n for n in nodes if n["id"] not in claimed and not is_trufflehog(n) and SEV.get(n["severity"], 0) >= 3
             and not any(n["source_url"].startswith(f"http://{h}/") for h in QUIET_HOSTS)]
    if extra:
        check("unexplained-findings", not strict_extra,
              f"{len(extra)} regex finding(s) >= medium no row explains: "
              f"{sorted(collections.Counter((n['secret_type'], n['severity']) for n in extra).items())}",
              None if strict_extra else "WARN")

    if phase in ("p1", "p2"):
        traced = [n for n in nodes if is_trufflehog(n) or th_alt(n) or "trufflehog" in validation(n)]
        if trufflehog == "off":
            check("trufflehog-off", not traced, "no TruffleHog trace in the graph" if not traced else
                  f"{len(traced)} node(s) carry TruffleHog data")
        else:
            check("trufflehog-ran", bool(traced), f"{len(traced)} node(s) carry TruffleHog data")
            orphans = [n for n in nodes if is_trufflehog(n) and n["parents"] < 1]
            check("trufflehog-parents", not orphans, "every TruffleHog-only node has a HAS_SECRET parent"
                  if not orphans else f"{len(orphans)} without a parent")
            rejected = [n for n in nodes if is_trufflehog(n) and n.get("validation_status") == "rejected"]
            check("trufflehog-never-rejected", not rejected, "no TruffleHog-only node is rejected (Rule V1)"
                  if not rejected else f"{len(rejected)} TruffleHog-only node(s) rejected")


def real_rows(path, nodes):
    with open(path, encoding="utf-8") as fh:
        rows = json.load(fh)["rows"]
    for row in rows:
        case = f"real:{row['name']} ({row['value_sha12']})"
        if not row.get("trufflehog_offline"):
            check(case, True, "TruffleHog did not detect it offline: no expectation", "SKIP")
            continue
        hit = [n for n in nodes if n["source_url"] == f"http://{row['host']}{row['file']}"
               and n["mt12"] == row["value_sha12"]]
        if not hit:
            check(case, False, "no node")
            continue
        node = hit[0]
        info = validation(node)
        by = info.get("checked_by") or (info.get("trufflehog") or {}).get("checked_by")
        ok = node.get("validation_status") == "validated" and (by == "trufflehog" or (info.get("trufflehog") or {})
                                                               .get("verified") is True)
        check(case, ok, f"{node['secret_type']} {node.get('validation_status')} (checked_by {by})",
              None if ok or node.get("validation_status") != "unknown" else "WARN")


def main():
    ap = argparse.ArgumentParser(description="Validate a js_secret_lab project against expected.json.")
    ap.add_argument("project_id")
    ap.add_argument("--phase", choices=("e0", "p0", "p1", "p2"), default="p1")
    ap.add_argument("--trufflehog", choices=("on", "off"), default="off")
    ap.add_argument("--real-expected", metavar="PATH", help="E3: expected_real.json from gen_lab.py --real-keys")
    ap.add_argument("--strict-extra", action="store_true", help="FAIL on unexplained findings >= medium")
    args = ap.parse_args()

    pid = check_pid(args.project_id)
    nodes = cypher_rows(SECRETS, pid)
    rows = load_rows()
    print(f"[*] project {pid}: {len(nodes)} js_recon Secret nodes "
          f"({dict(collections.Counter(n['detection_method'] for n in nodes))}); "
          f"phase {args.phase}, TruffleHog {args.trufflehog}; {len(rows)} expected rows")
    if not nodes:
        check("graph", False, "the project has no js_recon Secret")
    claimed = regex_rows(rows, nodes, args.phase)
    if args.phase in ("p1", "p2") and args.trufflehog == "on":
        trufflehog_rows(rows, nodes, claimed)
    global_checks(nodes, args.phase, args.trufflehog, args.strict_extra, claimed, pid)
    if args.real_expected:
        real_rows(args.real_expected, nodes)

    width = max(len(c) for _, c, _ in results)
    for level, case, detail in results:
        print(f"{level:<4}  {case:<{width}}  {detail}")
    counts = collections.Counter(level for level, _, _ in results)
    print(f"\n{counts['PASS']} PASS, {counts['FAIL']} FAIL, {counts['SKIP']} SKIP, "
          f"{counts['WARN']} WARN, {counts['INFO']} INFO")
    sys.exit(1 if counts["FAIL"] else 0)


if __name__ == "__main__":
    main()
