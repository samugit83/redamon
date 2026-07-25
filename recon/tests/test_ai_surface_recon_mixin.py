"""Unit tests for AiSurfaceReconMixin.update_graph_from_ai_surface_recon.

Uses a fake Neo4j driver/session that records every Cypher call and its
params, so we can assert the graph transform without a live database.

Run inside the recon image (graph_db is volume-mounted; neo4j driver present):
    docker run --rm --entrypoint python3 \
        -v "$PWD/recon:/app/recon:ro" -v "$PWD/graph_db:/app/graph_db:ro" -w /app \
        redamon-recon:latest recon/tests/test_ai_surface_recon_mixin.py
"""
from __future__ import annotations
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from graph_db.mixins.recon.ai_surface_recon_mixin import AiSurfaceReconMixin


RECON_JOB_PARAMS = {
    "recon_job_id": "job-ai-surface-123",
    "recon_job_started_at": "2026-07-24T10:11:12Z",
}


class FakeRecord(dict):
    def get(self, k, default=None):
        return dict.get(self, k, default)


class FakeResult:
    def __init__(self, single=None):
        self._single = single

    def single(self):
        return self._single


class FakeSession:
    def __init__(self):
        self.queries = []  # list[(query, params)]

    def run(self, query, **params):
        self.queries.append((query, params))
        # The finding link-check expects a .single() with a 'linked' bool.
        if "RETURN e IS NOT NULL AS linked" in query:
            return FakeResult(single=FakeRecord(linked=False))
        return FakeResult()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


class FakeDriver:
    def __init__(self, session):
        self._session = session

    def session(self):
        return self._session


class FakeClient(AiSurfaceReconMixin):
    def __init__(self, session):
        self.driver = FakeDriver(session)

    def _recon_job_params(self):
        return dict(RECON_JOB_PARAMS)


def _assert_seen_stamped(query, alias):
    assert (
        f"{alias}.first_seen = coalesce("
        f"{alias}.first_seen, datetime($recon_job_started_at))"
    ) in query
    assert (
        f"{alias}.first_seen_job_id = coalesce("
        f"{alias}.first_seen_job_id, $recon_job_id)"
    ) in query
    assert f"{alias}.last_seen = datetime($recon_job_started_at)" in query
    assert f"{alias}.last_seen_job_id = $recon_job_id" in query


def _assert_job_params(params):
    for name, value in RECON_JOB_PARAMS.items():
        assert params.get(name) == value


def _sample_payload():
    return {"ai_surface_recon": {
        "by_url": {
            "http://h": {
                "chat": {"path": "/v1/chat/completions", "ai_interface_type": "llm-chat",
                         "supports_streaming": True, "latency_p50_ms": 10.0,
                         "model_family_guess": "gpt"},
                "openapi": {"supports_tools": True, "tool_schema_ref": "/tmp/x.json"},
                "julius": {"service": "ollama", "category": "ai-runtime", "specificity": 100},
                "mcp": {"is_mcp": True, "path": "/mcp", "server_name": "demo",
                        "protocol_version": "2025-06-18", "tool_count": 1,
                        "capabilities": ["tools"], "auth_required": False,
                        "tools_hash": "abc",
                        "tools": [{"name": "send_email",
                                   "input_schema": {"properties": {"to": {}, "prompt": {}}},
                                   "annotations": {}}]},
            }
        },
        "findings": [{"id": "aisr_deadbeef", "type": "mcp_tool_poisoning", "severity": "high",
                      "name": "poison", "baseurl": "http://h", "path": "/mcp",
                      "tool_name": "send_email", "owasp_llm_id": "LLM01",
                      "atlas_technique": "AML.T0051", "evidence": "{}"}],
        "vector_db": [{"service": "qdrant", "host": "h", "ip": "1.2.3.4", "port": 6333,
                       "tech_name": "qdrant", "confirmed_via": "read"}],
    }}


def test_no_data_returns_error_stat():
    sess = FakeSession()
    client = FakeClient(sess)
    stats = client.update_graph_from_ai_surface_recon({}, "u", "p")
    assert stats["errors"] and "No ai_surface_recon data" in stats["errors"][0]
    assert not sess.queries


def test_full_payload_writes_expected_nodes():
    sess = FakeSession()
    client = FakeClient(sess)
    stats = client.update_graph_from_ai_surface_recon(_sample_payload(), "u", "p")
    assert stats["errors"] == [], stats["errors"]
    assert stats["endpoints_annotated"] >= 2   # chat + mcp endpoint
    assert stats["parameters_created"] == 2     # 'to' + 'prompt'
    assert stats["vulnerabilities_created"] == 1
    assert stats["technologies_promoted"] == 2  # julius service + vector-db

    joined = "\n".join(q for q, _ in sess.queries)
    assert "ai_tool_schema_ref" in joined
    assert "ai_mcp_server_name" in joined
    assert "HAS_VULNERABILITY" in joined
    assert "ai-vector-db" in joined
    assert "USES_TECHNOLOGY" in joined   # julius -> Technology promotion


def test_every_ai_surface_node_write_is_seen_stamped_with_job_params():
    sess = FakeSession()
    FakeClient(sess).update_graph_from_ai_surface_recon(_sample_payload(), "u", "p")

    blocks = [
        ("e.ai_model_ids", ("b", "e")),
        ("e.ai_mcp_server_name", ("b", "e")),
        ("MERGE (p:Parameter", ("p",)),
        ("ai-surface-recon-julius", ("t", "b", "e")),
        ("SET v += $props", ("v",)),
        ("t.category = 'ai-vector-db'", ("t",)),
    ]
    matched = {selector: 0 for selector, _ in blocks}
    for query, params in sess.queries:
        for selector, aliases in blocks:
            if selector not in query:
                continue
            matched[selector] += 1
            for alias in aliases:
                _assert_seen_stamped(query, alias)
            _assert_job_params(params)

    assert matched == {
        "e.ai_model_ids": 1,
        "e.ai_mcp_server_name": 1,
        "MERGE (p:Parameter": 2,
        "ai-surface-recon-julius": 1,
        "SET v += $props": 1,
        "t.category = 'ai-vector-db'": 1,
    }

    joined = "\n".join(query for query, _ in sess.queries)
    for relationship_alias in ("r", "r2", "r3"):
        assert f"{relationship_alias}.first_seen" not in joined
        assert f"{relationship_alias}.last_seen" not in joined


def test_julius_service_promoted_to_technology():
    sess = FakeSession()
    client = FakeClient(sess)
    client.update_graph_from_ai_surface_recon(_sample_payload(), "u", "p")
    tech_calls = [pr for q, pr in sess.queries if "MERGE (t:Technology" in q and "USES_TECHNOLOGY" in q]
    assert tech_calls, "julius service should MERGE a Technology + USES_TECHNOLOGY edge"
    names = {pr.get("name") for pr in tech_calls}
    assert "ollama" in names


def test_coalesce_used_for_endpoint_props():
    sess = FakeSession()
    client = FakeClient(sess)
    client.update_graph_from_ai_surface_recon(_sample_payload(), "u", "p")
    # every AI endpoint prop must be COALESCE-guarded (re-run safety)
    ep_queries = [q for q, _ in sess.queries if "MERGE (e:Endpoint" in q]
    assert ep_queries
    for q in ep_queries:
        for field in ("ai_interface_type", "ai_supports_tools", "ai_supports_streaming"):
            if field in q:
                assert f"COALESCE($" in q, f"{field} not COALESCE-guarded"


def test_finding_id_and_props_passed():
    sess = FakeSession()
    client = FakeClient(sess)
    client.update_graph_from_ai_surface_recon(_sample_payload(), "u", "p")
    vuln_calls = [(q, pr) for q, pr in sess.queries if "MERGE (v:Vulnerability" in q]
    assert vuln_calls
    _, params = vuln_calls[0]
    assert params["id"] == "aisr_deadbeef"
    assert params["props"]["source"] == "ai_surface_recon"
    assert params["props"]["ai_owasp_llm_id"] == "LLM01"


def test_prompt_param_flagged_injectable():
    sess = FakeSession()
    client = FakeClient(sess)
    client.update_graph_from_ai_surface_recon(_sample_payload(), "u", "p")
    param_calls = [pr for q, pr in sess.queries if "MERGE (p:Parameter" in q]
    by_name = {pr["name"]: pr for pr in param_calls}
    assert "prompt" in by_name and "to" in by_name
    # 'prompt' is in AI_PARAM_NAMES -> injectable True; 'to' is not -> None
    assert by_name["prompt"]["inj"] is True
    assert by_name["to"]["inj"] in (None, False)
    # arg_path resolved via mcp-tools-list dialect
    assert by_name["prompt"]["apath"] == "/inputSchema/properties/prompt"


def test_one_bad_host_does_not_abort():
    payload = _sample_payload()
    payload["ai_surface_recon"]["by_url"]["http://bad"] = None  # malformed
    sess = FakeSession()
    client = FakeClient(sess)
    stats = client.update_graph_from_ai_surface_recon(payload, "u", "p")
    # bad host recorded as error but good host + finding + vdb still processed
    assert any("http://bad" in e for e in stats["errors"])
    assert stats["vulnerabilities_created"] == 1
    assert stats["technologies_promoted"] == 2  # julius service + vector-db


def _host_endpoint_call(sess):
    """The chat/host-level Endpoint GET write (carries streaming + model_ids)."""
    for q, pr in sess.queries:
        if "MERGE (e:Endpoint" in q and "e.ai_model_ids" in q:
            return q, pr
    return None, None


def test_openapi_streaming_promotes_when_chat_absent():
    # No chat probe, but the OpenAPI spec advertises streaming -> must persist True.
    payload = {"ai_surface_recon": {"by_url": {"http://h": {
        "openapi": {"supports_tools": True, "supports_streaming": True}}}}}
    sess = FakeSession()
    FakeClient(sess).update_graph_from_ai_surface_recon(payload, "u", "p")
    q, pr = _host_endpoint_call(sess)
    assert q is not None, "host Endpoint write should fire on openapi-only host"
    assert "e.ai_supports_streaming" in q and "$streaming" in q
    assert pr["streaming"] is True, "openapi streaming must reach the graph"


def test_chat_streaming_false_not_overridden_by_silent_openapi():
    # Live probe saw a non-streaming chat surface; spec has no opinion -> keep False.
    payload = {"ai_surface_recon": {"by_url": {"http://h": {
        "chat": {"path": "/v1/chat/completions", "ai_interface_type": "llm-chat",
                 "supports_streaming": False},
        "openapi": {"supports_tools": True}}}}}
    sess = FakeSession()
    FakeClient(sess).update_graph_from_ai_surface_recon(payload, "u", "p")
    _, pr = _host_endpoint_call(sess)
    assert pr["streaming"] is False


def test_model_ids_persisted_merged_and_deduped():
    # model_ids come from BOTH openapi and julius; order-preserving dedupe.
    payload = {"ai_surface_recon": {"by_url": {"http://h": {
        "openapi": {"model_ids": ["gpt-4o", "gpt-4o-mini"], "model_family_guess": "gpt"},
        "julius": {"service": "vllm", "category": "ai-runtime",
                   "model_ids": ["gpt-4o", "llama3"]}}}}}
    sess = FakeSession()
    FakeClient(sess).update_graph_from_ai_surface_recon(payload, "u", "p")
    q, pr = _host_endpoint_call(sess)
    assert "e.ai_model_ids" in q and "$model_ids" in q
    assert pr["model_ids"] == ["gpt-4o", "gpt-4o-mini", "llama3"]


def test_model_ids_none_when_absent_keeps_coalesce_noop():
    # No model ids anywhere -> param is None so COALESCE preserves any prior value.
    payload = {"ai_surface_recon": {"by_url": {"http://h": {
        "chat": {"path": "/c", "ai_interface_type": "llm-chat"}}}}}
    sess = FakeSession()
    FakeClient(sess).update_graph_from_ai_surface_recon(payload, "u", "p")
    _, pr = _host_endpoint_call(sess)
    assert pr["model_ids"] is None


if __name__ == "__main__":
    failures = []
    passed = 0
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            try:
                fn(); print(f"  PASS  {name}"); passed += 1
            except AssertionError as e:
                print(f"  FAIL  {name}: {e}"); failures.append((name, str(e)))
            except Exception as e:
                print(f"  ERROR {name}: {type(e).__name__}: {e}")
                failures.append((name, f"{type(e).__name__}: {e}"))
    print(f"\n{passed} passed, {len(failures)} failed")
    sys.exit(1 if failures else 0)
