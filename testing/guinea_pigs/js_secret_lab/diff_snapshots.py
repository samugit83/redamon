#!/usr/bin/env python3
"""Diff two snapshot.py files: nodes added, removed and changed, by (label, id),
property by property.

    python3 diff_snapshots.py a.json b.json                 # exit 0 identical, 1 different
    python3 diff_snapshots.py a.json b.json --updated       # also list the nodes whose updated_at moved
    python3 diff_snapshots.py a.json b.json --ignore k1,k2  # more properties to ignore

Properties every run rewrites (discovered_at, ...) are ignored by default
(--no-default-ignore shows them). updated_at is reported apart: a refreshed
node is not a changed one. Values are the snapshot's own (hashed), so nothing
raw can show here.
"""
import argparse
import collections
import json
from urllib.parse import urlparse

DEFAULT_IGNORE = {"discovered_at", "created_at", "scan_timestamp", "last_seen", "last_seen_at"}


def load(path):
    with open(path, encoding="utf-8") as fh:
        snap = json.load(fh)
    return snap, {(n["label"], n["id"]): n for n in snap["nodes"]}


def describe(node):
    p = node["props"]
    kind = p.get("secret_type") or p.get("finding_type") or p.get("path") or ""
    where = p.get("source_url") or p.get("baseurl") or p.get("base_url") or ""
    return f"{node['label']} {node['id']} [{kind}] {where}"


def short(value, width=90):
    text = json.dumps(value, sort_keys=True)
    return text if len(text) <= width else text[:width - 3] + "..."


def host_of(node):
    p = node["props"]
    url = p.get("source_url") or p.get("baseurl") or p.get("base_url") or ""
    return urlparse(url).netloc or url.split("://")[0] or "?"


def main():
    ap = argparse.ArgumentParser(description="Diff two js_secret_lab graph snapshots.")
    ap.add_argument("a")
    ap.add_argument("b")
    ap.add_argument("--ignore", default="", help="comma-separated properties to ignore as well")
    ap.add_argument("--no-default-ignore", action="store_true")
    ap.add_argument("--updated", action="store_true", help="list the nodes whose updated_at moved")
    args = ap.parse_args()

    ignore = set() if args.no_default_ignore else set(DEFAULT_IGNORE)
    ignore |= {k.strip() for k in args.ignore.split(",") if k.strip()}
    sa, a = load(args.a)
    sb, b = load(args.b)
    print(f"a: {args.a} ({sa['project_id']}, {sa['taken_at']}) {sa['counts']}")
    print(f"b: {args.b} ({sb['project_id']}, {sb['taken_at']}) {sb['counts']}")
    if ignore:
        print(f"ignored properties: {', '.join(sorted(ignore))}")

    added = sorted(set(b) - set(a))
    removed = sorted(set(a) - set(b))
    print(f"\nadded ({len(added)}):")
    for key in added:
        print(f"  + {describe(b[key])}")
    print(f"removed ({len(removed)}):")
    for key in removed:
        print(f"  - {describe(a[key])}")

    changed, refreshed, stale = [], [], collections.Counter()
    for key in sorted(set(a) & set(b)):
        pa, pb = a[key]["props"], b[key]["props"]
        diffs = [(k, pa.get(k), pb.get(k)) for k in sorted(set(pa) | set(pb))
                 if k not in ignore and pa.get(k) != pb.get(k)]
        if a[key].get("parents") != b[key].get("parents"):
            diffs.append(("(HAS_SECRET parents)", a[key].get("parents"), b[key].get("parents")))
        if diffs:
            changed.append((key, diffs))
        if a[key].get("updated_at") != b[key].get("updated_at"):
            refreshed.append(key)
        else:
            stale[host_of(b[key])] += 1
    print(f"changed ({len(changed)}):")
    for key, diffs in changed:
        print(f"  ~ {describe(b[key])}")
        for prop, va, vb in diffs:
            print(f"      {prop}: {short(va)} -> {short(vb)}")

    common = len(set(a) & set(b))
    by_host = collections.Counter(host_of(b[k]) for k in refreshed)
    print(f"\nupdated_at moved on {len(refreshed)} of {common} common nodes"
          f" (by host: {dict(sorted(by_host.items()))}; unchanged by host: {dict(sorted(stale.items()))})")
    if args.updated:
        for key in refreshed:
            print(f"  ^ {describe(b[key])}")
    raise SystemExit(1 if added or removed or changed else 0)


if __name__ == "__main__":
    main()
