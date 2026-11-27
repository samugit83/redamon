"""Lap-2 — Resource Enum AI Classifier tests.

Covers:

  1. Catalogue shape — AI_PATH_PATTERNS, AI_RAG_PATH_PATTERNS, AI_PARAM_NAMES,
     AI_TOOL_ARG_PATH_DIALECTS are non-empty and well-formed
  2. Helper functions — match_ai_path, is_ai_rag_path, is_ai_prompt_param,
     resolve_ai_tool_arg_path: positive + negative + edge cases
  3. Per-catalogue-entry positive matches (parametrised) and no-false-positive
     guards against static and login paths
  4. Annotator wiring — _annotate_ai_endpoint_classifier walks organized_data
     and stamps the right properties under each toggle combination, including
     the master gate and the parent_is_ai gate for ambiguous RAG paths
  5. Live Neo4j — update_graph_from_resource_enum writes the new endpoint and
     parameter properties; re-running is idempotent
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import Pattern

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))
RECON_DIR = PROJECT_ROOT / "recon"
if str(RECON_DIR) not in sys.path:
    sys.path.insert(0, str(RECON_DIR))

from recon.helpers import ai_signal_catalog as cat
from recon.main_recon_modules.resource_enum import (
    _annotate_ai_endpoint_classifier,
    _build_parent_ai_map,
)


# ---------------------------------------------------------------------------
# Catalogue shape
# ---------------------------------------------------------------------------

def test_ai_path_patterns_shape():
    assert cat.AI_PATH_PATTERNS, "AI_PATH_PATTERNS empty"
    valid_enums = {
        "llm-chat", "llm-completion", "llm-embedding", "llm-tool-call",
        "sse-stream", "mcp", "llm-graphql", "non-llm",
    }
    for entry in cat.AI_PATH_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 2, f"bad path entry: {entry!r}"
        pattern, interface_type = entry
        assert isinstance(pattern, type(__import__("re").compile(""))), f"pattern is not a regex: {pattern!r}"
        assert interface_type in valid_enums, f"unknown ai_interface_type {interface_type!r}"


def test_ai_rag_path_patterns_shape():
    assert cat.AI_RAG_PATH_PATTERNS, "AI_RAG_PATH_PATTERNS empty"
    for entry in cat.AI_RAG_PATH_PATTERNS:
        assert isinstance(entry, tuple) and len(entry) == 2
        pattern, requires_parent_ai = entry
        assert isinstance(pattern, type(__import__("re").compile("")))
        assert isinstance(requires_parent_ai, bool)


def test_ai_param_names_shape():
    assert cat.AI_PARAM_NAMES, "AI_PARAM_NAMES empty"
    for name in cat.AI_PARAM_NAMES:
        assert isinstance(name, str) and name
        assert name == name.lower(), f"param name {name!r} must be lowercase"


def test_ai_tool_arg_path_dialects_shape():
    assert cat.AI_TOOL_ARG_PATH_DIALECTS, "AI_TOOL_ARG_PATH_DIALECTS empty"
    for entry in cat.AI_TOOL_ARG_PATH_DIALECTS:
        assert isinstance(entry, tuple) and len(entry) == 2
        dialect_name, pointer = entry
        assert isinstance(dialect_name, str) and dialect_name
        assert isinstance(pointer, str) and pointer.startswith("/")


def test_resource_enum_catalogues_extensive_enough():
    """Floor sizes so the catalogues can't silently regress to a stub."""
    assert len(cat.AI_PATH_PATTERNS) >= 30, f"AI_PATH_PATTERNS only has {len(cat.AI_PATH_PATTERNS)}"
    assert len(cat.AI_RAG_PATH_PATTERNS) >= 10, f"AI_RAG_PATH_PATTERNS only has {len(cat.AI_RAG_PATH_PATTERNS)}"
    assert len(cat.AI_PARAM_NAMES) >= 15, f"AI_PARAM_NAMES only has {len(cat.AI_PARAM_NAMES)}"
    assert len(cat.AI_TOOL_ARG_PATH_DIALECTS) >= 4, f"AI_TOOL_ARG_PATH_DIALECTS only has {len(cat.AI_TOOL_ARG_PATH_DIALECTS)}"


# ---------------------------------------------------------------------------
# match_ai_path
# ---------------------------------------------------------------------------

def test_match_ai_path_returns_llm_chat_for_openai():
    assert cat.match_ai_path("/v1/chat/completions") == "llm-chat"


def test_match_ai_path_returns_llm_chat_for_anthropic():
    assert cat.match_ai_path("/v1/messages") == "llm-chat"


def test_match_ai_path_returns_llm_chat_for_ollama():
    assert cat.match_ai_path("/api/chat") == "llm-chat"


def test_match_ai_path_returns_llm_chat_for_gemini_generate():
    assert cat.match_ai_path("/v1beta/models/gemini-1.5-pro:generateContent") == "llm-chat"


def test_match_ai_path_returns_llm_chat_for_gemini_stream_generate():
    assert cat.match_ai_path("/v1beta/models/gemini-1.5-pro:streamGenerateContent") == "llm-chat"


def test_match_ai_path_returns_llm_chat_for_cohere_v2():
    assert cat.match_ai_path("/v2/chat") == "llm-chat"


def test_match_ai_path_returns_llm_chat_for_groq_openai_prefix():
    assert cat.match_ai_path("/openai/v1/chat/completions") == "llm-chat"


def test_match_ai_path_returns_llm_completion_for_legacy_openai():
    assert cat.match_ai_path("/v1/completions") == "llm-completion"


def test_match_ai_path_returns_llm_completion_for_mistral_fim():
    assert cat.match_ai_path("/v1/fim/completions") == "llm-completion"


def test_match_ai_path_returns_llm_completion_for_ollama_generate():
    assert cat.match_ai_path("/api/generate") == "llm-completion"


def test_match_ai_path_returns_llm_embedding_for_openai():
    assert cat.match_ai_path("/v1/embeddings") == "llm-embedding"


def test_match_ai_path_returns_llm_embedding_for_ollama_embed():
    assert cat.match_ai_path("/api/embed") == "llm-embedding"


def test_match_ai_path_returns_llm_embedding_for_cohere_v2_embed():
    assert cat.match_ai_path("/v2/embed") == "llm-embedding"


def test_match_ai_path_returns_llm_embedding_for_gemini_embed():
    assert cat.match_ai_path("/v1beta/models/text-embedding-004:embedContent") == "llm-embedding"


def test_match_ai_path_returns_llm_tool_call_for_assistants_runs():
    assert cat.match_ai_path("/v1/threads/thread_abc/runs") == "llm-tool-call"


def test_match_ai_path_returns_llm_tool_call_for_responses_input_items():
    assert cat.match_ai_path("/v1/responses/resp_abc/input_items") == "llm-tool-call"


def test_match_ai_path_returns_sse_stream_for_tgi():
    assert cat.match_ai_path("/generate_stream") == "sse-stream"


def test_match_ai_path_returns_sse_stream_for_langserve_suffix():
    """LangServe exposes /<path>/stream for every runnable. The (?:^|/)stream
    pattern must match at suffix position, not only at start."""
    assert cat.match_ai_path("/agents/myagent/stream") == "sse-stream"
    assert cat.match_ai_path("/agents/myagent/stream_log") == "sse-stream"
    assert cat.match_ai_path("/agents/myagent/astream_events") == "sse-stream"


def test_match_ai_path_returns_mcp_for_canonical_paths():
    assert cat.match_ai_path("/mcp") == "mcp"
    assert cat.match_ai_path("/api/mcp") == "mcp"
    assert cat.match_ai_path("/sse") == "mcp"


def test_match_ai_path_returns_mcp_for_tools_list_suffix():
    """tools/list and resources/list may appear as suffix on REST shims."""
    assert cat.match_ai_path("/tools/list") == "mcp"
    assert cat.match_ai_path("/api/v1/tools/list") == "mcp"


def test_match_ai_path_returns_llm_graphql_for_graphql_path():
    assert cat.match_ai_path("/graphql") == "llm-graphql"
    assert cat.match_ai_path("/api/graphql") == "llm-graphql"
    assert cat.match_ai_path("/v1/graphql") == "llm-graphql"


def test_match_ai_path_returns_none_for_static_routes():
    """No false positive on common non-AI paths."""
    assert cat.match_ai_path("/about") is None
    assert cat.match_ai_path("/login") is None
    assert cat.match_ai_path("/api/users/123") is None
    assert cat.match_ai_path("/robots.txt") is None
    assert cat.match_ai_path("/static/css/main.css") is None
    assert cat.match_ai_path("/wp-admin") is None


def test_match_ai_path_case_insensitive():
    assert cat.match_ai_path("/V1/Chat/Completions") == "llm-chat"
    assert cat.match_ai_path("/API/CHAT") == "llm-chat"


def test_match_ai_path_empty_input():
    assert cat.match_ai_path("") is None
    assert cat.match_ai_path(None) is None  # type: ignore


def test_match_ai_path_with_trailing_slash():
    assert cat.match_ai_path("/v1/chat/completions/") == "llm-chat"


# ---------------------------------------------------------------------------
# is_ai_rag_path
# ---------------------------------------------------------------------------

def test_is_ai_rag_path_unambiguous_vendor_paths_fire_without_parent_ai():
    """OpenAI Vector Stores, Pinecone, Weaviate, Qdrant — all unambiguous."""
    assert cat.is_ai_rag_path("/v1/vector_stores") is True
    assert cat.is_ai_rag_path("/v1/vector_stores/vs_abc/search") is True
    assert cat.is_ai_rag_path("/v1/assistants") is True
    assert cat.is_ai_rag_path("/v1/threads") is True
    assert cat.is_ai_rag_path("/v1/threads/thread_abc/messages") is True
    assert cat.is_ai_rag_path("/vectors/upsert") is True
    assert cat.is_ai_rag_path("/v1/objects") is True
    assert cat.is_ai_rag_path("/v1/batch/objects") is True
    assert cat.is_ai_rag_path("/collections/mycol/points") is True
    assert cat.is_ai_rag_path("/collections/mycol/points/search") is True


def test_is_ai_rag_path_ambiguous_paths_require_parent_ai():
    """/search, /upload, /query and similar — generic, gated."""
    for p in ("/search", "/upload", "/files", "/query"):
        assert cat.is_ai_rag_path(p, parent_is_ai=False) is False, f"{p} should not fire without parent_is_ai"
        assert cat.is_ai_rag_path(p, parent_is_ai=True) is True, f"{p} should fire with parent_is_ai"


def test_is_ai_rag_path_empty_input():
    assert cat.is_ai_rag_path("") is False
    assert cat.is_ai_rag_path(None) is False  # type: ignore


def test_is_ai_rag_path_no_false_positive_on_static():
    assert cat.is_ai_rag_path("/about") is False
    assert cat.is_ai_rag_path("/login") is False
    assert cat.is_ai_rag_path("/api/users/123") is False


# ---------------------------------------------------------------------------
# is_ai_prompt_param
# ---------------------------------------------------------------------------

def test_is_ai_prompt_param_known_names():
    for name in ("prompt", "messages", "system", "input", "instructions",
                 "contents", "inputs", "tools", "arguments", "query", "text"):
        assert cat.is_ai_prompt_param(name) is True, f"{name!r} should be a known prompt param"


def test_is_ai_prompt_param_case_insensitive():
    assert cat.is_ai_prompt_param("PROMPT") is True
    assert cat.is_ai_prompt_param("Messages") is True
    assert cat.is_ai_prompt_param("SystemInstruction") is True


def test_is_ai_prompt_param_strips_whitespace():
    assert cat.is_ai_prompt_param("  prompt  ") is True


def test_is_ai_prompt_param_negative_for_common_form_fields():
    for name in ("username", "password", "email", "csrf_token", "page", "id"):
        assert cat.is_ai_prompt_param(name) is False, f"{name!r} should NOT be a prompt param"


def test_is_ai_prompt_param_empty_input():
    assert cat.is_ai_prompt_param("") is False
    assert cat.is_ai_prompt_param(None) is False  # type: ignore


# ---------------------------------------------------------------------------
# resolve_ai_tool_arg_path
# ---------------------------------------------------------------------------

def test_resolve_ai_tool_arg_path_openai_functions():
    spec = {"parameters": {"properties": {"query": {"type": "string"}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "openai-functions", "query") == "/parameters/properties/query"


def test_resolve_ai_tool_arg_path_anthropic_tools():
    spec = {"input_schema": {"properties": {"city": {"type": "string"}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "anthropic-tools", "city") == "/input_schema/properties/city"


def test_resolve_ai_tool_arg_path_mcp_tools_list():
    spec = {"inputSchema": {"properties": {"path": {"type": "string"}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "mcp-tools-list", "path") == "/inputSchema/properties/path"


def test_resolve_ai_tool_arg_path_unknown_dialect_returns_none():
    spec = {"parameters": {"properties": {"q": {}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "totally-fake-dialect", "q") is None


def test_resolve_ai_tool_arg_path_missing_param_returns_none():
    spec = {"parameters": {"properties": {"a": {}}}}
    assert cat.resolve_ai_tool_arg_path(spec, "openai-functions", "b") is None


def test_resolve_ai_tool_arg_path_empty_spec_returns_none():
    assert cat.resolve_ai_tool_arg_path({}, "openai-functions", "q") is None
    assert cat.resolve_ai_tool_arg_path(None, "openai-functions", "q") is None  # type: ignore


# ---------------------------------------------------------------------------
# _build_parent_ai_map
# ---------------------------------------------------------------------------

def test_build_parent_ai_map_empty_when_no_http_probe():
    assert _build_parent_ai_map({}) == {}


def test_build_parent_ai_map_picks_up_ai_tagged_baseurls():
    recon_data = {
        "http_probe": {
            "by_url": {
                "https://host1.test/": {"is_ai_framework_detected": True},
                "https://host2.test/api/v1": {"is_ai_framework_detected": True},
                "https://host3.test/": {"is_ai_framework_detected": False},
                "https://host4.test/": {},
            }
        }
    }
    parent_ai = _build_parent_ai_map(recon_data)
    assert parent_ai.get("https://host1.test") is True
    assert parent_ai.get("https://host2.test") is True
    assert "https://host3.test" not in parent_ai
    assert "https://host4.test" not in parent_ai


# ---------------------------------------------------------------------------
# _annotate_ai_endpoint_classifier — toggle gating + correctness
# ---------------------------------------------------------------------------

ON = {
    "RESOURCE_ENUM_AI_CLASSIFIER_ENABLED": True,
    "RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED": True,
    "RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED": True,
    "RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED": True,
}


def _make_organized(base_url: str, endpoints: dict) -> dict:
    return {"by_base_url": {base_url: {"endpoints": endpoints}}}


def test_annotator_classifies_chat_endpoint():
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {
            "parameters": {"query": [], "body": [{"name": "messages"}, {"name": "system"}, {"name": "model"}], "path": []}
        }
    })
    summary = _annotate_ai_endpoint_classifier(organized, ON, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert ep["ai_interface_type"] == "llm-chat"
    body = ep["parameters"]["body"]
    by_name = {p["name"]: p for p in body}
    assert by_name["messages"].get("is_ai_prompt_injectable") is True
    assert by_name["system"].get("is_ai_prompt_injectable") is True
    assert by_name["model"].get("is_ai_prompt_injectable") is not True
    assert summary["paths"] >= 1
    assert summary["prompt_params"] >= 2


def test_annotator_marks_non_llm_endpoints():
    organized = _make_organized("https://app.test", {
        "/about": {"parameters": {"query": [], "body": [], "path": []}},
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    ep = organized["by_base_url"]["https://app.test"]["endpoints"]["/about"]
    assert ep["ai_interface_type"] == "non-llm"


def test_annotator_master_toggle_off_skips_everything():
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {
            "parameters": {"query": [], "body": [{"name": "messages"}], "path": []}
        }
    })
    settings = dict(ON, RESOURCE_ENUM_AI_CLASSIFIER_ENABLED=False)
    summary = _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert "ai_interface_type" not in ep
    body = ep["parameters"]["body"]
    assert "is_ai_prompt_injectable" not in body[0]
    assert summary == {"paths": 0, "rag_paths": 0, "prompt_params": 0}


def test_annotator_path_toggle_off_does_not_stamp_anything():
    """When the path classifier is off, the annotator must NOT stamp
    ai_interface_type (not even the 'non-llm' sentinel). The whole point
    of having a per-channel toggle is for operators to opt out of pollution."""
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {"parameters": {"query": [], "body": [], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_PATH_CLASSIFIER_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]
    assert "ai_interface_type" not in ep


def test_annotator_rag_toggle_off_skips_rag_tag():
    organized = _make_organized("https://app.test", {
        "/v1/vector_stores": {"parameters": {"query": [], "body": [], "path": []}}
    })
    settings = dict(ON, RESOURCE_ENUM_AI_RAG_PATH_FLAG_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    ep = organized["by_base_url"]["https://app.test"]["endpoints"]["/v1/vector_stores"]
    assert "is_ai_rag_ingest" not in ep


def test_annotator_param_toggle_off_skips_param_tag():
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {
            "parameters": {"query": [], "body": [{"name": "prompt"}], "path": []}
        }
    })
    settings = dict(ON, RESOURCE_ENUM_AI_PARAM_INJECTABLE_FLAG_ENABLED=False)
    _annotate_ai_endpoint_classifier(organized, settings, {})
    body = organized["by_base_url"]["https://api.test"]["endpoints"]["/v1/chat/completions"]["parameters"]["body"]
    assert "is_ai_prompt_injectable" not in body[0]


def test_annotator_does_not_flag_params_on_non_llm_endpoint():
    """A parameter named 'text' on a contact form is not prompt-injectable.
    The annotator must require the parent endpoint to be AI-classified first."""
    organized = _make_organized("https://app.test", {
        "/contact": {"parameters": {"query": [], "body": [{"name": "text"}, {"name": "prompt"}], "path": []}}
    })
    _annotate_ai_endpoint_classifier(organized, ON, {})
    ep = organized["by_base_url"]["https://app.test"]["endpoints"]["/contact"]
    assert ep["ai_interface_type"] == "non-llm"
    for p in ep["parameters"]["body"]:
        assert "is_ai_prompt_injectable" not in p


def test_annotator_rag_ambiguous_path_requires_parent_ai():
    """/search on a non-AI host stays plain; on an AI-tagged host it's RAG."""
    ambig_eps = {"/search": {"parameters": {"query": [], "body": [], "path": []}}}

    # Non-AI parent — no RAG flag
    organized_a = _make_organized("https://shop.test", dict(ambig_eps))
    _annotate_ai_endpoint_classifier(organized_a, ON, {})
    ep_a = organized_a["by_base_url"]["https://shop.test"]["endpoints"]["/search"]
    assert "is_ai_rag_ingest" not in ep_a

    # AI-tagged parent — RAG flag fires
    organized_b = _make_organized("https://llm.test", dict(ambig_eps))
    recon_data = {"http_probe": {"by_url": {"https://llm.test/v1/chat": {"is_ai_framework_detected": True}}}}
    _annotate_ai_endpoint_classifier(organized_b, ON, recon_data)
    ep_b = organized_b["by_base_url"]["https://llm.test"]["endpoints"]["/search"]
    assert ep_b.get("is_ai_rag_ingest") is True


def test_annotator_summary_counters_increment():
    """Verify counters reflect what fired:
    /v1/chat/completions → llm-chat (paths += 1) + 2 prompt params
    /v1/vector_stores    → no path match, RAG matches (rag_paths += 1)
                           — but endpoint_is_ai gate triggers param scan
    /about               → no path/RAG match, non-llm; param scan skipped
    """
    organized = _make_organized("https://api.test", {
        "/v1/chat/completions": {"parameters": {"query": [], "body": [{"name": "prompt"}, {"name": "messages"}], "path": []}},
        "/v1/vector_stores":    {"parameters": {"query": [], "body": [], "path": []}},
        "/about":               {"parameters": {"query": [], "body": [{"name": "username"}], "path": []}},
    })
    summary = _annotate_ai_endpoint_classifier(organized, ON, {})
    assert summary["paths"] == 1, f"expected paths=1, got {summary['paths']}"
    assert summary["rag_paths"] == 1, f"expected rag_paths=1, got {summary['rag_paths']}"
    assert summary["prompt_params"] == 2, f"expected prompt_params=2, got {summary['prompt_params']}"


def test_annotator_none_settings_returns_zero_summary():
    organized = _make_organized("https://api.test", {"/v1/chat/completions": {"parameters": {"query": [], "body": [], "path": []}}})
    summary = _annotate_ai_endpoint_classifier(organized, None, {})
    assert summary == {"paths": 0, "rag_paths": 0, "prompt_params": 0}


# ---------------------------------------------------------------------------
# Live Neo4j — resource_mixin Endpoint + Parameter AI props
# ---------------------------------------------------------------------------

def _neo4j_driver():
    try:
        from neo4j import GraphDatabase  # type: ignore
    except Exception:
        return None
    try:
        drv = GraphDatabase.driver("bolt://localhost:7687", auth=("neo4j", "changeme123"))
        drv.verify_connectivity()
        return drv
    except Exception:
        return None


def _cleanup(session, uid: str, pid: str):
    session.run(
        """
        MATCH (n)
        WHERE (n:BaseURL OR n:Endpoint OR n:Parameter OR n:Technology)
          AND n.user_id = $u AND n.project_id = $p
        DETACH DELETE n
        """,
        u=uid, p=pid,
    )


def _resource_mixin_instance(driver):
    from graph_db.mixins.recon.resource_mixin import ResourceMixin

    class _Scratch(ResourceMixin):
        def __init__(self, drv):
            self.driver = drv

    return _Scratch(driver)


def test_neo4j_resource_mixin_writes_endpoint_ai_props():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_resource_mixin_writes_endpoint_ai_props (neo4j unreachable)")
        return
    uid, pid = "lap2-test-user", "lap2-resource-endpoint-ai-props"
    try:
        with drv.session() as s:
            _cleanup(s, uid, pid)
        mixin = _resource_mixin_instance(drv)
        recon_data = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],
                                "ai_interface_type": "llm-chat",
                                "is_ai_rag_ingest": None,
                                "parameters": {"query": [], "body": [], "path": []},
                                "parameter_count": {"total": 0, "query": 0, "body": 0, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(recon_data, uid, pid)
        with drv.session() as s:
            row = s.run(
                """
                MATCH (e:Endpoint {path:'/v1/chat/completions', method:'POST',
                                   baseurl:'https://api.test.invalid',
                                   user_id:$u, project_id:$p})
                RETURN e.ai_interface_type AS t, e.is_ai_rag_ingest AS r
                """,
                u=uid, p=pid,
            ).single()
            assert row is not None, "Endpoint not created"
            assert row["t"] == "llm-chat"
            _cleanup(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_resource_mixin_writes_param_ai_props():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_resource_mixin_writes_param_ai_props (neo4j unreachable)")
        return
    uid, pid = "lap2-test-user", "lap2-resource-param-ai-props"
    try:
        with drv.session() as s:
            _cleanup(s, uid, pid)
        mixin = _resource_mixin_instance(drv)
        recon_data = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/chat/completions": {
                                "methods": ["POST"],
                                "ai_interface_type": "llm-chat",
                                "parameters": {
                                    "query": [],
                                    "body": [
                                        {"name": "messages", "type": "array", "is_ai_prompt_injectable": True},
                                        {"name": "model", "type": "string"},
                                    ],
                                    "path": [],
                                },
                                "parameter_count": {"total": 2, "query": 0, "body": 2, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(recon_data, uid, pid)
        with drv.session() as s:
            msg = s.run(
                """
                MATCH (p:Parameter {name:'messages', position:'body',
                                    endpoint_path:'/v1/chat/completions',
                                    baseurl:'https://api.test.invalid',
                                    user_id:$u, project_id:$p})
                RETURN p.is_ai_prompt_injectable AS flag
                """,
                u=uid, p=pid,
            ).single()
            model = s.run(
                """
                MATCH (p:Parameter {name:'model', position:'body',
                                    endpoint_path:'/v1/chat/completions',
                                    baseurl:'https://api.test.invalid',
                                    user_id:$u, project_id:$p})
                RETURN p.is_ai_prompt_injectable AS flag
                """,
                u=uid, p=pid,
            ).single()
            assert msg is not None and msg["flag"] is True, "messages should be prompt-injectable"
            assert model is not None and (model["flag"] is None or model["flag"] is False), \
                "model param should not be prompt-injectable"
            _cleanup(s, uid, pid)
    finally:
        drv.close()


def test_neo4j_resource_mixin_repeat_runs_idempotent():
    drv = _neo4j_driver()
    if drv is None:
        print("SKIP: test_neo4j_resource_mixin_repeat_runs_idempotent (neo4j unreachable)")
        return
    uid, pid = "lap2-test-user", "lap2-resource-idempotent"
    try:
        with drv.session() as s:
            _cleanup(s, uid, pid)
        mixin = _resource_mixin_instance(drv)
        recon_data = {
            "resource_enum": {
                "by_base_url": {
                    "https://api.test.invalid": {
                        "endpoints": {
                            "/v1/embeddings": {
                                "methods": ["POST"],
                                "ai_interface_type": "llm-embedding",
                                "parameters": {"query": [], "body": [{"name": "input", "is_ai_prompt_injectable": True}], "path": []},
                                "parameter_count": {"total": 1, "query": 0, "body": 1, "path": 0},
                            }
                        },
                        "summary": {"methods": {"POST": 1}, "categories": {}},
                    }
                }
            }
        }
        mixin.update_graph_from_resource_enum(recon_data, uid, pid)
        mixin.update_graph_from_resource_enum(recon_data, uid, pid)
        with drv.session() as s:
            n_ep = s.run(
                "MATCH (e:Endpoint {user_id:$u, project_id:$p}) RETURN count(e) AS n",
                u=uid, p=pid,
            ).single()["n"]
            n_param = s.run(
                "MATCH (p:Parameter {user_id:$u, project_id:$p}) RETURN count(p) AS n",
                u=uid, p=pid,
            ).single()["n"]
            assert n_ep == 1, f"expected 1 Endpoint after re-run, got {n_ep}"
            assert n_param == 1, f"expected 1 Parameter after re-run, got {n_param}"
            _cleanup(s, uid, pid)
    finally:
        drv.close()
