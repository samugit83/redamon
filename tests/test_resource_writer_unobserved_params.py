"""The resource writer hands "not observed" to its Cypher as null, and the Cypher keeps the stored value (D5).

update_graph_from_resource_enum runs here against a fake session that records
every statement; the values a real database ends up with are proven in
test_resource_enum_parameter_facts_graph_live.py. Here: a body or path
Parameter whose caller said nothing about input_type / required reaches the
Cypher as null, a value the caller did state reaches it unchanged, and no
statement assigns has_parameters, a parameter count or Parameter.source
outright.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402

BASE = "https://app.example.com"


class _Result:
    def single(self):
        return {"linked": 0}


class _Session:
    def __init__(self, calls):
        self.calls = calls

    def run(self, query, **params):
        self.calls.append((" ".join(query.split()), params))
        return _Result()

    def execute_write(self, work):
        return work(self)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


class _Driver:
    def __init__(self):
        self.calls = []

    def session(self):
        return _Session(self.calls)


def _write(endpoints: dict):
    mixin = ResourceMixin()
    mixin.driver = _Driver()
    stats = mixin.update_graph_from_resource_enum(
        {"domain": "example.com", "subdomains": ["app.example.com"],
         "resource_enum": {"by_base_url": {BASE: {"endpoints": endpoints}}, "forms": []}},
        "u1", "p1")
    assert stats["errors"] == []
    return mixin.driver.calls


def _parameter_writes(calls, position):
    return [(q, p) for q, p in calls
            if q.startswith("MERGE (p:Parameter") and p.get("position") == position]


def _signup(body, path):
    return {"/signup/{plan}": {"methods": ["POST"], "sources": ["arjun"],
                               "parameters": {"query": [], "body": body, "path": path}}}


def test_a_body_and_path_parameter_the_caller_said_nothing_about_reach_the_cypher_as_null():
    calls = _write(_signup([{"name": "email"}], [{"name": "plan"}]))

    [(_, body)] = _parameter_writes(calls, "body")
    [(_, path)] = _parameter_writes(calls, "path")
    assert (body["input_type"], body["required"]) == (None, None)
    assert path["required"] is None


def test_what_the_caller_stated_reaches_the_cypher_unchanged():
    calls = _write(_signup([{"name": "password", "input_type": "password", "required": True}],
                           [{"name": "plan", "required": False}]))

    [(_, body)] = _parameter_writes(calls, "body")
    [(_, path)] = _parameter_writes(calls, "path")
    assert (body["input_type"], body["required"]) == ("password", True)
    assert path["required"] is False


def test_a_null_parameter_count_does_not_fail_the_endpoint():
    calls = _write({"/about": {"methods": ["GET"], "sources": ["gau"], "parameter_count": None}})

    [(_, endpoint)] = [(q, p) for q, p in calls if q.startswith("MERGE (e:Endpoint")]
    assert (endpoint["has_params"], endpoint["query_count"]) == (False, 0)


def test_no_statement_assigns_a_parameter_fact_outright():
    calls = _write({**_signup([{"name": "email"}], [{"name": "plan"}]),
                    "/search": {"methods": ["GET"], "sources": ["katana"],
                                "parameters": {"query": [{"name": "q"}], "body": [], "path": []},
                                "parameter_count": {"query": 1, "body": 0, "path": 0, "total": 1}}})
    cypher = "\n".join(q for q, _ in calls)

    # Each of these, assigned a bare parameter or literal, overwrites what an
    # earlier writer stored with what this caller did not observe.
    for outright in (r"e\.has_parameters = \$has_params\s*,",
                     r"e\.(query|body|path)_param_count = \$\w+\s*,",
                     r"p\.source = 'resource_enum'",
                     r"p\.input_type = \$input_type\s*,",
                     r"p\.required = \$required\s*,"):
        assert not re.search(outright, cypher), outright
