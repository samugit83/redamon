"""In-memory Neo4j stand-in for the TruffleHog graph-write tests.

Models just enough Cypher to check the write CONTRACT — which MERGE keys are
used, what a scoped DETACH DELETE actually removes, which relationships are
created — without a live database. Shared by the scoped-clear unit suite and the
end-to-end integration suite so both assert against the same semantics; the live
suite covers the same paths against a real Neo4j when a stack is up.
"""

import re

from graph_db.mixins.base_mixin import BaseMixin
from graph_db.mixins.secret_mixin import SecretMixin


class FakeResult:
    def __init__(self, record):
        self._record = record

    def single(self):
        return self._record


class FakeSession:
    """Models just enough Cypher to test the write contract: MERGE creates or
    updates a node keyed by its full MERGE map, DETACH DELETE removes matching
    nodes, and relationship MERGE records an edge."""

    def __init__(self, store):
        self.store = store

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        q = " ".join(query.split())

        merge_node = re.match(
            r"MERGE \(\w+:(\w+) \{(.*?)\}\) SET", q)
        if merge_node:
            label, key_src = merge_node.group(1), merge_node.group(2)
            keys = dict(re.findall(r"(\w+): \$(\w+)", key_src))
            node_key = (label, tuple(sorted((k, params[v]) for k, v in keys.items())))
            props = dict(params.get("props") or {})
            existing = self.store["nodes"].get(node_key, {})
            existing.update(props)
            existing["__label__"] = label
            self.store["nodes"][node_key] = existing
            self.store["merge_keys"].append((label, tuple(sorted(keys))))
            return FakeResult({"linked": 1})

        # Only the scoped clear's shape is modelled. The X7 prune that runs
        # after a successful ingest MATCHes without a label and is proven
        # against a real database (tests/test_ingest_then_prune_graph_live.py);
        # here it is a no-op like any other unmodelled query.
        labelled_delete = re.search(r"MATCH \(\w+:(\w+)\)", q)
        if "DETACH DELETE" in q and labelled_delete:
            label = labelled_delete.group(1)
            deleted = 0
            for node_key in list(self.store["nodes"]):
                node_label, key_tuple = node_key
                if node_label != label:
                    continue
                node = self.store["nodes"][node_key]
                if node.get("user_id") != params.get("uid"):
                    continue
                if node.get("project_id") != params.get("pid"):
                    continue
                if "n.source = $source" in q:
                    node_source = node.get("source")
                    matches = node_source == params.get("source")
                    if "n.source IS NULL" in q:
                        matches = matches or node_source is None
                    if not matches:
                        continue
                del self.store["nodes"][node_key]
                deleted += 1
            self.store["deletes"].append((label, params.get("source", "__ALL__")))
            return FakeResult({"deleted": deleted})

        rel = re.search(r"MERGE \(\w+\)-\[:(\w+)\]->\(\w+\)", q)
        if rel:
            self.store["rels"].append(rel.group(1))
            return FakeResult({"linked": 1})

        return FakeResult(None)


class FakeDriver:
    def __init__(self, store):
        self.store = store

    def session(self):
        return FakeSession(self.store)


class FakeClient(SecretMixin, BaseMixin):
    def __init__(self):
        self.store = {"nodes": {}, "rels": [], "deletes": [], "merge_keys": []}
        self.driver = FakeDriver(self.store)

    def nodes_of(self, label):
        return [n for k, n in self.store["nodes"].items() if k[0] == label]

    def findings(self, source=None):
        out = self.nodes_of("MultiscannerFinding")
        return [f for f in out if source is None or f.get("source") == source]


def scan_payload(source, asset_kind, findings, target="acme", **extra):
    payload = {
        "source": source,
        "source_label": source.title(),
        "asset_kind": asset_kind,
        "run_id": source,
        "target": target,
        "verification_enabled": True,
        "status": "completed",
        "statistics": {"total_findings": len(findings), "assets_scanned": 1},
        "findings": findings,
    }
    payload.update(extra)
    return payload


def finding(asset, location="app.py", detector="AWS", line=1, **extra):
    f = {
        "source": "", "asset": asset, "location": location,
        "detector_name": detector, "line": line, "verified": False,
        "validation_status": "unvalidated", "finding_kind": "secret",
        "redacted": "AKIA****", "extra_data": "{}",
    }
    f.update(extra)
    return f


