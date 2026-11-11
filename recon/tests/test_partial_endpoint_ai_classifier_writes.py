"""The partial Endpoint AI Classifier writes only the AI fields, on this run's hosts (R-27, D5).

The partial module read every Endpoint of the project and wrote the classified
dict back through update_graph_from_resource_enum, the full crawl writer. That
writer sets what a crawl measures: urls_found (1 when absent), source,
the parameter counts, and on each Parameter its category and sample_values
([] when absent). So one classification run reset every endpoint's urls_found
and every parameter's sample values, and it did so on every host of the
project, those this run does not cover and those the RoE excludes included.

The real partial module runs, with the real _prepare_scope (scope groups and
RoE) and the real ResourceMixin writers; only Neo4j is a fake that answers the
module's reads and records every statement. Only example.com / example.org
names are used.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path
from unittest import mock

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402

ROOT = "example.com"
OTHER_ROOT = "example.org"
PID = "proj-r27"
UID = "u1"
IN_SCOPE = "https://app.example.com"
OTHER_GROUP = "https://shop.example.org"       # another scan root of the project, not this run's
ROE_EXCLUDED = "https://legacy.example.com"    # under this run's root, excluded by the RoE

# (baseurl, path, method): the graph's Endpoint nodes.
ENDPOINTS = [
    (IN_SCOPE, "/v1/chat/completions", "POST"),
    (IN_SCOPE, "/login", "GET"),
    (OTHER_GROUP, "/v1/chat/completions", "POST"),
    (ROE_EXCLUDED, "/api/chat", "POST"),
]
# (baseurl, endpoint path, name, position): their Parameters.
PARAMETERS = [
    (IN_SCOPE, "/v1/chat/completions", "messages", "body"),
    (IN_SCOPE, "/login", "user", "query"),
    (OTHER_GROUP, "/v1/chat/completions", "messages", "body"),
    (ROE_EXCLUDED, "/api/chat", "prompt", "body"),
]

# What the classifier produces: nothing else may be written.
AI_FIELDS = {"ai_interface_type", "is_ai_rag_ingest", "is_ai_prompt_injectable"}


class _Result(list):
    def single(self):
        return self[0] if self else None

    def consume(self):
        return None

    def data(self):
        return list(self)


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False

    def close(self):
        pass

    def execute_write(self, work, *args, **kwargs):
        return work(self, *args, **kwargs)

    execute_read = execute_write

    def run(self, cypher, parameters=None, **params):
        params = {**(parameters or {}), **params}
        self.calls.append((cypher, params))
        rows = _Result()
        if "RETURN e.baseurl AS baseurl, e.path AS path, e.method AS method" in cypher:
            rows.extend({"baseurl": b, "path": p, "method": m} for b, p, m in ENDPOINTS)
        elif "HAS_PARAMETER" in cypher and "p.name AS name" in cypher:
            rows.extend({"baseurl": b, "path": p, "name": n, "position": pos}
                        for b, p, n, pos in PARAMETERS)
        elif "RETURN d.name AS name" in cypher:
            rows.extend({"name": n} for n in (ROOT, OTHER_ROOT))
        return rows


class _Client(ResourceMixin):
    calls: list = []

    def __init__(self, *_a, **_k):
        self.driver = self

    def session(self, **_k):
        return _Session(_Client.calls)

    def close(self):
        pass


def _settings(**extra) -> dict:
    groups = [{"scanRoot": r, "orgDomain": r, "mode": "enumerate", "includeRoot": True,
               "exactHosts": []} for r in (ROOT, OTHER_ROOT)]
    return {"TARGET_DOMAIN": ROOT, "IP_MODE": False, "DOMAIN_BATCH_MODE": True,
            "VERIFY_DOMAIN_OWNERSHIP": False, "ROE_ENABLED": True,
            "ROE_EXCLUDED_HOSTS": ["legacy.example.com"], "SCOPE_GROUPS": groups, **extra}


def _run(settings: dict):
    """Run the real partial module over ROOT only; return its write statements."""
    import recon.partial_recon as pr
    from recon.partial_recon_modules import endpoint_ai_classification as module

    cfg = {"tool_id": "EndpointAiClassifier", "domains": [ROOT], "include_graph_targets": True}
    assert pr._prepare_scope(cfg, settings, PID) == {}
    _Client.calls = []
    with mock.patch("graph_db.neo4j_client.Neo4jClient", _Client), \
         mock.patch.dict("os.environ", {"USER_ID": UID, "PROJECT_ID": PID}):
        outcome = module.run_endpoint_ai_classifier(cfg)
    writes = [(_strip(c), p) for c, p in _Client.calls if _WRITE.search(_strip(c))]
    return writes, outcome


# ---------------------------------------------------------------------------
# Cypher inspection: which properties a statement assigns
# ---------------------------------------------------------------------------

_WRITE = re.compile(r"\b(SET|MERGE|CREATE|DELETE|REMOVE)\b")
# Longest first: "ON CREATE SET" is one clause, not "ON CREATE" then "SET".
_KEYWORDS = ("OPTIONAL MATCH", "ON CREATE SET", "ON MATCH SET", "MATCH", "MERGE", "CREATE", "WITH",
             "RETURN", "WHERE", "UNWIND", "FOREACH", "CALL", "REMOVE", "DETACH", "DELETE", "SET")
_SET_CLAUSES = ("SET", "ON CREATE SET", "ON MATCH SET")


def _strip(cypher: str) -> str:
    """The statement without `//` comments, on one line."""
    return " ".join(re.sub(r"//[^\n]*", "", cypher).split())


def _clauses(cypher: str):
    """(keyword, body) for each clause at bracket depth 0."""
    out, depth, i, start, current = [], 0, 0, 0, None
    while i < len(cypher):
        ch = cypher[i]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif depth == 0 and (i == 0 or not (cypher[i - 1].isalnum() or cypher[i - 1] == "_")):
            kw = next((k for k in _KEYWORDS if cypher.startswith(k, i)
                       and not (cypher[i + len(k):i + len(k) + 1].isalnum())), None)
            if kw:
                if current is not None:
                    out.append((current, cypher[start:i]))
                current, start = kw, i + len(kw)
                i += len(kw)
                continue
        i += 1
    if current is not None:
        out.append((current, cypher[start:]))
    return out


def _split_items(body: str):
    items, depth, start = [], 0, 0
    for i, ch in enumerate(body):
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
        elif ch == "," and depth == 0:
            items.append(body[start:i])
            start = i + 1
    items.append(body[start:])
    return items


def _assigned(cypher: str) -> set:
    """Every property a SET clause assigns; '*' for a map merge (`n += $props`)."""
    out = set()
    for kw, body in _clauses(cypher):
        if kw not in _SET_CLAUSES:
            continue
        for item in _split_items(body):
            m = re.match(r"\s*\w+\.(\w+)\s*=", item)
            if m:
                out.add(m.group(1))
            elif re.match(r"\s*\w+\s*\+=", item):
                out.add("*")
    return out


def _strings(value):
    if isinstance(value, str):
        yield value
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v)


def _dicts(value):
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _dicts(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            yield from _dicts(v)


def _written_with(writes, **expected) -> bool:
    """Some statement's parameters hold a mapping with every expected key/value."""
    return any(all(d.get(k) == v for k, v in expected.items())
               for _c, params in writes for d in _dicts(params))


# ---------------------------------------------------------------------------
# The tests
# ---------------------------------------------------------------------------

def test_the_classifier_assigns_only_the_ai_fields():
    writes, _ = _run(_settings())

    assert writes, "the classifier wrote nothing"
    assigned = set().union(*(_assigned(c) for c, _ in writes))
    assert assigned <= AI_FIELDS, f"fields the classifier did not measure: {sorted(assigned - AI_FIELDS)}"


def test_the_classifier_never_creates_a_node():
    writes, _ = _run(_settings())

    assert [c for c, _ in writes if re.search(r"\b(MERGE|CREATE)\b", c)] == []


def test_every_node_the_classifier_writes_is_matched_on_the_tenant():
    writes, _ = _run(_settings())

    for cypher, params in writes:
        for label, props in re.findall(r"\(\w*:(\w+)\s*\{([^}]*)\}", cypher):
            assert "user_id" in props and "project_id" in props, (label, cypher)
        values = set(_strings(params))
        assert {UID, PID} <= values, cypher


def test_hosts_outside_the_run_are_not_written():
    writes, _ = _run(_settings())

    written = " ".join(s for _c, p in writes for s in _strings(p))
    assert "shop.example.org" not in written      # another scan root, not this run's
    assert "legacy.example.com" not in written    # the RoE excludes it


def test_the_in_scope_classification_still_lands():
    writes, _ = _run(_settings())

    assert _written_with(writes, baseurl=IN_SCOPE, path="/v1/chat/completions",
                         ai_interface_type="llm-chat")
    assert _written_with(writes, name="messages", is_ai_prompt_injectable=True)


def test_without_the_roe_exclusion_that_host_is_classified():
    writes, _ = _run(_settings(ROE_ENABLED=False))

    assert _written_with(writes, baseurl=ROE_EXCLUDED, path="/api/chat", ai_interface_type="llm-chat")
    written = " ".join(s for _c, p in writes for s in _strings(p))
    assert "shop.example.org" not in written


def test_a_classifier_with_nothing_to_say_writes_nothing():
    writes, _ = _run(_settings(RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED=False,
                               RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED=False,
                               RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED=False))

    assert writes == []


def test_a_failed_write_fails_the_run():
    from recon.partial_recon_modules.helpers import run_exit_code

    def refuse(*_a, **_k):
        raise RuntimeError("Neo4j went away")

    with mock.patch.object(_Session, "execute_write", refuse):
        _writes, outcome = _run(_settings())

    assert outcome == {ROOT: "failed: graph write"}
    assert run_exit_code(outcome) == 1


# ---------------------------------------------------------------------------
# The shared crawl writer: a partial caller that did not measure a field
# ---------------------------------------------------------------------------

def _crawl_write(entry: dict):
    """update_graph_from_resource_enum on one /login entry; its Endpoint and query Parameter writes."""
    _Client.calls = []
    _Client().update_graph_from_resource_enum(
        {"domain": ROOT, "subdomains": ["app.example.com"],
         "resource_enum": {"by_base_url": {IN_SCOPE: {"endpoints": {"/login": entry}}}}}, UID, PID)
    statements = [(_strip(c), p) for c, p in _Client.calls]
    endpoint = next(s for s in statements if s[0].startswith("MERGE (e:Endpoint"))
    parameter = next(s for s in statements if s[0].startswith("MERGE (p:Parameter"))
    return endpoint, parameter


def _assigned_in(cypher: str, clause: str) -> dict:
    """{property: expression} for the SET items of one clause kind."""
    out = {}
    for kw, body in _clauses(cypher):
        if kw != clause:
            continue
        for item in _split_items(body):
            m = re.match(r"\s*\w+\.(\w+)\s*=\s*(.*)$", item.strip())
            if m:
                out[m.group(1)] = m.group(2).strip()
    return out


GAU_LOGIN = {"methods": ["GET"], "category": "other", "sources": ["gau"],
             "parameters": {"query": [{"name": "user", "type": "string"}], "body": [], "path": []}}


def test_an_unmeasured_urls_found_reaches_the_writer_as_null_and_keeps_the_stored_count():
    (cypher, params), _ = _crawl_write(GAU_LOGIN)

    assert params["urls_found"] is None
    assert _assigned_in(cypher, "SET")["urls_found"] == "coalesce($urls_found, e.urls_found, 1)"


def test_source_is_written_only_when_the_writer_creates_the_endpoint():
    (cypher, _params), _ = _crawl_write(GAU_LOGIN)

    assert _assigned_in(cypher, "ON CREATE SET")["source"] == "'resource_enum'"
    assert "source" not in _assigned_in(cypher, "SET")
    assert "source" not in _assigned_in(cypher, "ON MATCH SET")


def test_a_parameter_without_values_or_category_keeps_the_stored_ones():
    _, (cypher, params) = _crawl_write(GAU_LOGIN)

    assert (params["category"], params["sample_values"]) == ("other", [])
    assigned = _assigned_in(cypher, "SET")
    assert assigned["sample_values"].startswith("CASE WHEN size($sample_values) > 0 THEN $sample_values")
    assert "coalesce(p.sample_values, $sample_values)" in assigned["sample_values"]
    assert assigned["category"].startswith("CASE WHEN coalesce($category, 'other') = 'other'")
    assert "THEN p.category ELSE $category END" in assigned["category"]


def test_a_crawl_that_measured_them_still_sends_its_values():
    measured = {**GAU_LOGIN, "urls_found": 7, "sources": ["katana"],
                "parameters": {"query": [{"name": "user", "category": "auth_params",
                                          "sample_values": ["alice"]}], "body": [], "path": []}}
    (_c, ep_params), (_p, param_params) = _crawl_write(measured)

    assert ep_params["urls_found"] == 7
    assert (param_params["category"], param_params["sample_values"]) == ("auth_params", ["alice"])
