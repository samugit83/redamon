#!/usr/bin/env python3
"""Server-side enforcement tests for the /graph/exec proxy endpoint (DP5).

The worker (redagraph) no longer holds Neo4j creds — it asks the agent to run
graph queries. ALL enforcement (read-only, tenant scoping, fixed schema/types
queries, no raw/unscoped path) must happen HERE so a compromised worker cannot
bypass it. Run inside the agent container: cd /app && python3 tests/test_graph_exec.py
"""
import asyncio
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = 0
FAIL = 0


def check(desc, cond):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS {desc}")
    else:
        FAIL += 1
        print(f"  FAIL {desc}")


def run(coro):
    return asyncio.new_event_loop().run_until_complete(coro)


class _FakeSession:
    def __init__(self, capture):
        self.capture = capture

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, params=None):
        self.capture["q"] = query
        self.capture["p"] = params or {}
        return []  # empty result set


class _FakeDriver:
    def __init__(self, capture):
        self.capture = capture

    def session(self):
        return _FakeSession(self.capture)


def main():
    from unittest import mock
    import api

    def req(**kw):
        return api.GraphExecRequest(**kw)

    print("=== read-only enforcement (server-side, authoritative) ===")
    for write in ["CREATE (n:Foo)", "MATCH (n:Foo) DELETE n", "MATCH (n:Foo) SET n.x=1", "MERGE (n:Foo)"]:
        resp = run(api.graph_exec(req(op="cypher", cypher=write, user_id="U", project_id="P")))
        check(f"write rejected 403: {write[:24]}", resp.status_code == 403)

    print("=== un-scoped query refused (no labelled pattern) ===")
    resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n) RETURN n", user_id="U", project_id="P")))
    check("MATCH (n) RETURN n -> 400 (cannot scope)", resp.status_code == 400)

    print("=== op=cypher: tenant filter injected + executed ===")
    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n:Subdomain) RETURN n.name AS name", user_id="U", project_id="P")))
    check("labelled read -> 200", resp.status_code == 200)
    check("tenant filter injected into executed query", "$tenant_user_id" in cap.get("q", ""))
    check("tenant params bound from request", cap.get("p", {}).get("tenant_user_id") == "U")

    print("=== op=types / op=schema use FIXED server queries (worker can't alter) ===")
    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        run(api.graph_exec(req(op="types", user_id="U", project_id="P")))
    check("types query is tenant-scoped", "$tenant_user_id" in cap.get("q", ""))
    # op=types never reaches scope_query, so the mute exclusion every agent
    # query gets for free has to be written into the fixed query by hand. Without
    # it the worker sees suppressed findings in the node-type counts, and `Muted`
    # itself is reported as a node type.
    check("types query excludes muted findings", "NOT n:Muted" in cap.get("q", ""))
    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        run(api.graph_exec(req(op="schema", user_id="U", project_id="P")))
    check("schema runs the fixed visualization call", "db.schema.visualization" in cap.get("q", ""))

    print("=== op=cypher: the worker cannot ask about suppressed findings ===")
    # Mute must be invisible to the sandbox exactly as it is to the agent: the
    # label is refused by scope_query, not scoped, so there is no probe for it.
    for probe in ["MATCH (n:Muted) RETURN n",
                  "MATCH (v:Vulnerability) WHERE v:Muted RETURN v",
                  "MATCH (v:Vulnerability) WHERE NOT v:Muted RETURN v"]:
        resp = run(api.graph_exec(req(op="cypher", cypher=probe, user_id="U", project_id="P")))
        check(f"muted probe refused 400: {probe[:34]}", resp.status_code == 400)

    cap = {}
    with mock.patch.object(api, "_graph_exec_get_driver", return_value=_FakeDriver(cap)):
        run(api.graph_exec(req(op="cypher", cypher="MATCH (v:Vulnerability) RETURN v", user_id="U", project_id="P")))
    check("worker read excludes muted findings", "!Muted" in cap.get("q", ""))

    print("=== the BYPASS attempt: no raw/unscoped op exists ===")
    # A compromised worker cannot ask for an arbitrary unscoped query: there is no
    # 'raw' op, op=cypher forces a labelled pattern + filter, and unknown ops 400.
    resp = run(api.graph_exec(req(op="raw", cypher="MATCH (n) RETURN n", user_id="U", project_id="P")))
    check("unknown op 'raw' -> 400 (no unscoped escape)", resp.status_code == 400)
    resp = run(api.graph_exec(req(op="cypher", cypher="", user_id="U", project_id="P")))
    check("empty cypher -> 400", resp.status_code == 400)
    resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n:Foo) RETURN n", user_id="", project_id="P")))
    check("missing tenant identity -> 400", resp.status_code == 400)

    print("=== op=cypher blocks apoc.atomic.* (E8 residual, landed with S8) ===")
    resp = run(api.graph_exec(req(op="cypher", cypher="MATCH (n:Foo) CALL apoc.atomic.add(n,'x',1) RETURN n", user_id="U", project_id="P")))
    check("apoc.atomic.* rejected 403", resp.status_code == 403)

    print("=== S8/I8/D7: /graph/exec and /emergency-stop-all require internal auth ===")
    # Both use the AUTH-ONLY dependency (no LLM rate-limit / daily cap) — graph
    # reads are cheap high-frequency, not billed LLM calls (regression guard).
    from llm_guard import require_internal_auth, require_internal_auth_only

    def _route_deps(path):
        for r in api.app.routes:
            if getattr(r, "path", None) == path:
                return [d.call for d in getattr(r, "dependant", None).dependencies] if getattr(r, "dependant", None) else []
        return None

    ge_deps = _route_deps("/graph/exec")
    es_deps = _route_deps("/emergency-stop-all")
    check("/graph/exec requires internal auth (auth-only)", ge_deps is not None and require_internal_auth_only in ge_deps)
    check("/emergency-stop-all requires internal auth (auth-only)", es_deps is not None and require_internal_auth_only in es_deps)
    check("/graph/exec is NOT LLM-rate-limited (no require_internal_auth)", require_internal_auth not in (ge_deps or []))

    # Regression: auth-only dependency authenticates but never throttles, even
    # across a bulk graph walk (>60 calls that would trip the 60-token bucket).
    import asyncio as _asyncio
    from starlette.requests import Request as _Req
    from llm_guard import _key_ok as _kok  # noqa
    os.environ["SCANNER_API_KEY"] = "scoped-xyz"

    async def _call_auth_only(hdr):
        scope = {"type": "http", "headers": [(b"x-internal-key", hdr.encode())] if hdr else [], "client": ("1.2.3.4", 9)}
        req = _Req(scope)
        try:
            await require_internal_auth_only(req)
            return True
        except Exception:
            return False

    ok_count = sum(1 for _ in range(200) if run(_call_auth_only("scoped-xyz")))
    check("auth-only allows 200 consecutive authed calls (no rate limit)", ok_count == 200)
    check("auth-only rejects a bad key (401)", run(_call_auth_only("wrong")) is False)
    os.environ.pop("SCANNER_API_KEY", None)

    print("=== /graph/triage is MASTER-key only (the sandbox must not reach it) ===")
    # The kali-sandbox holds SCANNER_API_KEY by design and NOT INTERNAL_API_KEY
    # (docker-compose.yml). require_internal_auth_only accepts both, which is
    # right for the read-only fixed-op /graph/exec and wrong for an endpoint
    # that WRITES suppression state: a compromised worker could hide findings
    # from the operator and the agent, or stamp triage_source='human' so a later
    # AI pass would refuse to correct it.
    from llm_guard import require_master_internal_auth
    tri_deps = _route_deps("/graph/triage")
    check("/graph/triage exists", tri_deps is not None)
    check("/graph/triage requires the MASTER key", require_master_internal_auth in (tri_deps or []))
    check("/graph/triage does NOT accept the scoped scanner key",
          require_internal_auth_only not in (tri_deps or []))
    check("/graph/exec still accepts the scanner key (the worker needs reads)",
          require_internal_auth_only in (ge_deps or []))

    os.environ["INTERNAL_API_KEY"] = "master-key"
    os.environ["SCANNER_API_KEY"] = "scanner-key"

    async def _call_master(hdr):
        scope = {"type": "http", "headers": [(b"x-internal-key", hdr.encode())] if hdr else [], "client": ("1.2.3.4", 9)}
        try:
            await require_master_internal_auth(_Req(scope))
            return True
        except Exception:
            return False

    check("master key accepted", run(_call_master("master-key")) is True)
    check("SCANNER key REJECTED on the triage endpoint", run(_call_master("scanner-key")) is False)
    check("no key rejected", run(_call_master("")) is False)
    os.environ.pop("INTERNAL_API_KEY", None)
    os.environ.pop("SCANNER_API_KEY", None)

    print()
    print(f"RESULT: PASS={PASS} FAIL={FAIL}")
    return 0 if FAIL == 0 else 1


def test_graph_exec():
    """pytest entrypoint: run the script-style checks; main() returns
    non-zero on any failed check (bucket-1 runner-compat conversion)."""
    assert main() == 0


if __name__ == "__main__":
    sys.exit(main())
