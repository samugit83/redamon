#!/usr/bin/env python3
"""BloodHound JSON → NetworkX path-finder for the RedAmon AD kill-chain skill.

No Neo4j. State persists in a JSON file between calls.
Edges carry a `weight` reflecting exploitation difficulty so shortest_path
returns the operationally-easiest chain, not just the edge-count-minimal one.
"""
import argparse
import json
import sys
import zipfile
from collections import Counter
from pathlib import Path

import networkx as nx

STATE = Path("/tmp/adkc/bhgraph.json")

EDGE_WEIGHT = {
    "MemberOf": 1,
    "Contains": 1,
    "GPLink": 1,
    "DCSync": 1,
    "GetChanges": 1,
    "GetChangesAll": 1,
    "AdminTo": 2,
    "CanRDP": 2,
    "CanPSRemote": 2,
    "HasSession": 2,
    "AddMember": 2,
    "ForceChangePassword": 2,
    "ReadGMSAPassword": 2,
    "ReadLAPSPassword": 2,
    "ExecuteDCOM": 3,
    "GenericAll": 3,
    "GenericWrite": 3,
    "AddKeyCredentialLink": 3,
    "SQLAdmin": 3,
    "Owns": 3,
    "WriteOwner": 4,
    "WriteDACL": 4,
    "AllowedToDelegate": 4,
    "AllowedToAct": 5,
    "HasSIDHistory": 5,
}
DEFAULT_WEIGHT = 5


def _add_edge(g, u, v, etype):
    g.add_edge(u, v, type=etype, weight=EDGE_WEIGHT.get(etype, DEFAULT_WEIGHT))


def _iter_sources(sources):
    for s in sources:
        p = Path(s)
        if p.suffix == ".zip":
            with zipfile.ZipFile(p) as zf:
                for name in zf.namelist():
                    yield name, zf.read(name)
        elif p.suffix == ".json":
            yield p.name, p.read_bytes()
        elif p.is_dir():
            for j in sorted(p.rglob("*.json")):
                yield j.name, j.read_bytes()
            for z in sorted(p.rglob("*.zip")):
                with zipfile.ZipFile(z) as zf:
                    for name in zf.namelist():
                        yield name, zf.read(name)


def _scalar_props(props):
    return {k: v for k, v in (props or {}).items()
            if isinstance(v, (str, int, float, bool))}


def load(sources):
    g = nx.DiGraph()
    for _name, raw in _iter_sources(sources):
        try:
            doc = json.loads(raw)
        except Exception:
            continue
        obj_type = (doc.get("meta") or {}).get("type", "unknown")
        for item in doc.get("data") or []:
            oid = item.get("ObjectIdentifier")
            if not oid:
                continue
            g.add_node(oid, type=obj_type, **_scalar_props(item.get("Properties")))

            pgs = item.get("PrimaryGroupSID")
            if pgs:
                _add_edge(g, oid, pgs, "MemberOf")

            for ace in item.get("Aces") or []:
                p_sid = ace.get("PrincipalSID")
                right = ace.get("RightName")
                if p_sid and right:
                    _add_edge(g, p_sid, oid, right)

            for member in item.get("Members") or []:
                m_id = member.get("ObjectIdentifier") if isinstance(member, dict) else None
                if m_id:
                    _add_edge(g, m_id, oid, "MemberOf")

            for collection, edge_type, direction in [
                ("Sessions", "HasSession", "out"),
                ("LocalAdmins", "AdminTo", "in"),
                ("RemoteDesktopUsers", "CanRDP", "in"),
                ("PSRemoteUsers", "CanPSRemote", "in"),
                ("DcomUsers", "ExecuteDCOM", "in"),
                ("SQLAdmins", "SQLAdmin", "in"),
            ]:
                block = item.get(collection) or {}
                results = block.get("Results") if isinstance(block, dict) else None
                for entry in results or []:
                    peer = (entry.get("UserSID")
                            or entry.get("ObjectIdentifier")
                            or entry.get("MemberId"))
                    if not peer:
                        continue
                    if direction == "out":
                        _add_edge(g, oid, peer, edge_type)
                    else:
                        _add_edge(g, peer, oid, edge_type)

            for d in item.get("AllowedToDelegate") or []:
                t_sid = d.get("ObjectIdentifier") if isinstance(d, dict) else d
                if t_sid:
                    _add_edge(g, oid, t_sid, "AllowedToDelegate")

            for d in item.get("AllowedToAct") or []:
                p_sid = d.get("ObjectIdentifier") if isinstance(d, dict) else d
                if p_sid:
                    _add_edge(g, p_sid, oid, "AllowedToAct")

            for sid_hist in item.get("HasSIDHistory") or []:
                t_sid = sid_hist.get("ObjectIdentifier") if isinstance(sid_hist, dict) else sid_hist
                if t_sid:
                    _add_edge(g, oid, t_sid, "HasSIDHistory")

            for link in item.get("Links") or []:
                t_sid = link.get("GUID") or link.get("ObjectIdentifier")
                if t_sid:
                    _add_edge(g, oid, t_sid, "GPLink")

            for child in item.get("ChildObjects") or []:
                c_sid = child.get("ObjectIdentifier") if isinstance(child, dict) else child
                if c_sid:
                    _add_edge(g, oid, c_sid, "Contains")

    STATE.parent.mkdir(parents=True, exist_ok=True)
    with open(STATE, "w") as f:
        json.dump(nx.node_link_data(g, edges="edges"), f)
    print(f"Loaded {g.number_of_nodes()} nodes, {g.number_of_edges()} edges → {STATE}")


def _load():
    if not STATE.exists():
        sys.exit("No graph state. Run: bhgraph load <zip|dir|json>")
    with open(STATE) as f:
        return nx.node_link_graph(json.load(f), edges="edges", directed=True)


def _save(g):
    with open(STATE, "w") as f:
        json.dump(nx.node_link_data(g, edges="edges"), f)


def _resolve(g, needle):
    if needle in g:
        return needle
    up = needle.upper()
    head = up.split("@")[0]
    for n, d in g.nodes(data=True):
        if (d.get("name") or "").upper() == up:
            return n
        if (d.get("samaccountname") or "").upper() == head:
            return n
    return None


def _find_targets(g, label_type, contains):
    up = contains.upper()
    return [n for n, d in g.nodes(data=True)
            if d.get("type") == label_type
            and up in (d.get("name") or "").upper()]


def _print_path(g, path):
    for i, sid in enumerate(path):
        name = g.nodes[sid].get("name") or sid
        typ = g.nodes[sid].get("type", "?")
        if i == 0:
            print(f"{name}  ({typ})")
        else:
            ed = g.get_edge_data(path[i-1], sid, {})
            edge_type = ed.get("type", "?")
            w = ed.get("weight", "?")
            print(f"  --[{edge_type} w={w}]-->  {name}  ({typ})")


def own(names):
    g = _load()
    hits = 0
    for name in names:
        sid = _resolve(g, name)
        if sid:
            g.nodes[sid]["owned"] = True
            hits += 1
            print(f"[owned] {g.nodes[sid].get('name') or sid}")
        else:
            print(f"[miss]  {name}")
    _save(g)
    print(f"{hits} node(s) marked owned.")


def _shortest_weighted_from_owned(g, targets):
    owned = [n for n, d in g.nodes(data=True) if d.get("owned")]
    if not owned:
        sys.exit("No owned nodes. Run: bhgraph own <name|sid>")
    best = None
    best_cost = None
    for s in owned:
        for t in targets:
            try:
                cost, path = nx.single_source_dijkstra(g, s, t, weight="weight")
            except nx.NetworkXNoPath:
                continue
            except nx.NodeNotFound:
                continue
            if best_cost is None or cost < best_cost:
                best_cost = cost
                best = path
    return best, best_cost


def path_to_da():
    g = _load()
    targets = _find_targets(g, "groups", "DOMAIN ADMINS")
    if not targets:
        sys.exit("No Domain Admins group found.")
    path, cost = _shortest_weighted_from_owned(g, targets)
    if not path:
        print("No path from any owned node to Domain Admins.")
        return
    print(f"Easiest path — {len(path)-1} hop(s), total weight {cost}:\n")
    _print_path(g, path)


def path_to(target):
    g = _load()
    tgt = _resolve(g, target)
    if not tgt:
        sys.exit(f"Target '{target}' not found.")
    path, cost = _shortest_weighted_from_owned(g, [tgt])
    if not path:
        print("No path.")
        return
    print(f"Easiest path — {len(path)-1} hop(s), total weight {cost}:\n")
    _print_path(g, path)


def kerberoastable():
    g = _load()
    rows = [d.get("name") for _, d in g.nodes(data=True)
            if d.get("type") == "users"
            and d.get("hasspn") is True
            and d.get("enabled", True)]
    for name in sorted(x for x in rows if x):
        print(name)
    print(f"\n{len(rows)} kerberoastable user(s).")


def asreproastable():
    g = _load()
    rows = [d.get("name") for _, d in g.nodes(data=True)
            if d.get("type") == "users"
            and d.get("dontreqpreauth") is True
            and d.get("enabled", True)]
    for name in sorted(x for x in rows if x):
        print(name)
    print(f"\n{len(rows)} AS-REProastable user(s).")


def unconstrained():
    g = _load()
    rows = [(d.get("type"), d.get("name")) for _, d in g.nodes(data=True)
            if d.get("unconstraineddelegation") is True]
    for typ, name in sorted(rows):
        print(f"{typ}\t{name}")
    print(f"\n{len(rows)} principal(s) with unconstrained delegation.")


def dcsyncers():
    g = _load()
    hits = set()
    for n, d in g.nodes(data=True):
        if d.get("type") != "domains":
            continue
        for pred in g.predecessors(n):
            et = g.get_edge_data(pred, n, {}).get("type", "")
            if et in ("GetChanges", "GetChangesAll", "DCSync"):
                name = g.nodes[pred].get("name") or pred
                hits.add((name, et))
    for name, et in sorted(hits):
        print(f"{name}\t{et}")
    print(f"\n{len(hits)} DCSync-enabling right(s).")


def high_value():
    g = _load()
    rows = [(d.get("type"), d.get("name")) for _, d in g.nodes(data=True)
            if d.get("highvalue") is True]
    for typ, name in sorted(rows):
        print(f"{typ}\t{name}")
    print(f"\n{len(rows)} high-value target(s).")


def lookup(name):
    g = _load()
    sid = _resolve(g, name)
    if not sid:
        sys.exit(f"'{name}' not in graph.")
    d = g.nodes[sid]
    print(f"SID:     {sid}")
    print(f"Type:    {d.get('type')}")
    print(f"Name:    {d.get('name')}")
    print(f"Owned:   {d.get('owned', False)}")
    print(f"Enabled: {d.get('enabled')}")
    print("\nIncoming (who can act on me):")
    for pred in g.predecessors(sid):
        ed = g.get_edge_data(pred, sid, {})
        et = ed.get("type", "?")
        w = ed.get("weight", "?")
        pn = g.nodes[pred].get("name") or pred
        print(f"  {pn} --[{et} w={w}]--> me")
    print("\nOutgoing (what I can do):")
    for succ in g.successors(sid):
        ed = g.get_edge_data(sid, succ, {})
        et = ed.get("type", "?")
        w = ed.get("weight", "?")
        sn = g.nodes[succ].get("name") or succ
        print(f"  me --[{et} w={w}]--> {sn}")


def stats():
    g = _load()
    node_types = Counter(d.get("type", "?") for _, d in g.nodes(data=True))
    edge_types = Counter(d.get("type", "?") for _, _, d in g.edges(data=True))
    owned = sum(1 for _, d in g.nodes(data=True) if d.get("owned"))
    print(f"Nodes: {g.number_of_nodes()}")
    for t, c in sorted(node_types.items(), key=lambda x: -x[1]):
        print(f"  {t:20s} {c}")
    print(f"\nEdges: {g.number_of_edges()}")
    for t, c in sorted(edge_types.items(), key=lambda x: -x[1])[:20]:
        print(f"  {t:30s} {c}")
    print(f"\nOwned principals: {owned}")


def main():
    ap = argparse.ArgumentParser(prog="bhgraph")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("load"); s.add_argument("sources", nargs="+")
    s = sub.add_parser("own"); s.add_argument("names", nargs="+")
    sub.add_parser("path-to-da")
    s = sub.add_parser("path-to"); s.add_argument("target")
    sub.add_parser("kerberoastable")
    sub.add_parser("asreproastable")
    sub.add_parser("unconstrained")
    sub.add_parser("dcsyncers")
    sub.add_parser("high-value")
    s = sub.add_parser("lookup"); s.add_argument("name")
    sub.add_parser("stats")
    a = ap.parse_args()
    {
        "load": lambda: load(a.sources),
        "own": lambda: own(a.names),
        "path-to-da": path_to_da,
        "path-to": lambda: path_to(a.target),
        "kerberoastable": kerberoastable,
        "asreproastable": asreproastable,
        "unconstrained": unconstrained,
        "dcsyncers": dcsyncers,
        "high-value": high_value,
        "lookup": lambda: lookup(a.name),
        "stats": stats,
    }[a.cmd]()


if __name__ == "__main__":
    main()
