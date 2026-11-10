"""Unit + integration tests for the ai_surface_recon module.

Pure helpers (candidate gathering, host gate, finding id, sse parse, tool hash)
plus MCP detection against a fake session and a fully mocked end-to-end run.

Run inside the recon image:
    docker run --rm --entrypoint python3 -v "$PWD/recon:/app/recon:ro" -w /app \
        redamon-recon:latest recon/tests/test_ai_surface_recon_module.py
"""
from __future__ import annotations
import json
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from recon.main_recon_modules import ai_surface_recon as m


class FakeResp:
    def __init__(self, status=200, text="", headers=None):
        self.status_code = status
        self.text = text
        self.headers = headers or {}

    def json(self):
        return json.loads(self.text)


class FakeSession:
    def __init__(self, routes):
        self.routes = routes
        self.headers = {}

    def _resp(self, method, url):
        from urllib.parse import urlparse
        path = urlparse(url).path or "/"
        r = self.routes.get((method, path))
        if r is None:
            raise m.requests.RequestException("no route")
        return r

    def post(self, url, data=None, json=None, headers=None, timeout=None,
             allow_redirects=False, verify=True):
        return self._resp("POST", url)

    def get(self, url, headers=None, timeout=None, allow_redirects=False, verify=True):
        return self._resp("GET", url)


# --- host gate + candidate gathering ----------------------------------------
def test_host_gate_via_http_probe_flag():
    cr = {"http_probe": {"by_url": {"http://h/": {"is_ai_framework_detected": True}}},
          "port_scan": {}}
    assert m._host_has_ai_signal("http://h", cr) is True
    assert m._host_has_ai_signal("http://other", cr) is False


def test_host_gate_no_substring_false_positive():
    # http://api.x.com must NOT match a different host that merely contains it
    cr = {"http_probe": {"by_url": {"http://api.x.com.evil/": {"is_ai_framework_detected": True}}},
          "port_scan": {}}
    assert m._host_has_ai_signal("http://api.x.com", cr) is False
    # exact host still matches
    cr2 = {"http_probe": {"by_url": {"http://api.x.com:8080/": {"is_ai_framework_detected": True}}},
           "port_scan": {}}
    assert m._host_has_ai_signal("http://api.x.com", cr2) is True


def test_host_gate_via_ai_port():
    cr = {"http_probe": {"by_url": {}},
          "port_scan": {"by_host": {"h": {"ports": [11434]}}}}  # ollama port
    assert m._host_has_ai_signal("http://h", cr) is True


def test_gather_candidates_picks_classified_endpoints():
    cr = {
        "resource_enum": {"by_base_url": {"http://h": {"endpoints": {
            "/v1/chat/completions": {"methods": ["POST"], "ai_interface_type": "llm-chat"},
            "/about": {"methods": ["GET"], "ai_interface_type": "non-llm"},
        }}}},
        "http_probe": {"by_url": {"http://h/": {"is_ai_framework_detected": True}}},
        "port_scan": {},
    }
    cands = m._gather_candidates(cr, {})
    assert "http://h" in cands
    paths = [e["path"] for e in cands["http://h"]["endpoints"]]
    assert "/v1/chat/completions" in paths
    # /about is non-llm but host is AI -> still included (host_ai gate), acceptable


def test_gather_candidates_skips_non_ai_host_without_classified_eps():
    cr = {
        "resource_enum": {"by_base_url": {"http://plain": {"endpoints": {
            "/about": {"methods": ["GET"], "ai_interface_type": "non-llm"},
        }}}},
        "http_probe": {"by_url": {}}, "port_scan": {},
    }
    cands = m._gather_candidates(cr, {})
    assert "http://plain" not in cands


def test_gather_candidates_adds_ai_host_with_no_crawl():
    cr = {"resource_enum": {"by_base_url": {}},
          "http_probe": {"by_url": {"https://ai.example/": {"is_ai_framework_detected": True}}},
          "port_scan": {}}
    cands = m._gather_candidates(cr, {})
    assert "https://ai.example" in cands and cands["https://ai.example"]["host_is_ai"] is True


# --- finding id / sse / tool hash -------------------------------------------
def test_finding_id_deterministic_and_prefixed():
    a = m._mk_finding("mcp_tool_poisoning", "high", "x", "http://h", "/mcp", "send", "LLM01", "AML.T0051", None)
    b = m._mk_finding("mcp_tool_poisoning", "high", "x", "http://h", "/mcp", "send", "LLM01", "AML.T0051", None)
    assert a["id"] == b["id"] and a["id"].startswith("aisr_")
    c = m._mk_finding("mcp_tool_poisoning", "high", "x", "http://h", "/mcp", "OTHER", "LLM01", "AML.T0051", None)
    assert c["id"] != a["id"]


def test_first_sse_json():
    assert m._first_sse_json('data: {"result": 1}\n') == {"result": 1}
    assert m._first_sse_json("event: ping\nno data here") is None
    assert m._first_sse_json("data: not-json") is None


def test_tool_hash_stable_and_sensitive():
    t1 = {"name": "send", "description": "Send a message", "inputSchema": {"x": 1}}
    t2 = {"name": "send", "description": "Send a message", "inputSchema": {"x": 1}}
    t3 = {"name": "send", "description": "Send a message (HACKED)", "inputSchema": {"x": 1}}
    assert m._tool_hash(t1) == m._tool_hash(t2)
    assert m._tool_hash(t1) != m._tool_hash(t3)  # rug-pull detectable


# --- MCP detection (raw handshake) ------------------------------------------
def test_mcp_detect_streamable_http():
    init = {"jsonrpc": "2.0", "id": 1, "result": {
        "protocolVersion": "2025-06-18",
        "capabilities": {"tools": {}},
        "serverInfo": {"name": "demo", "version": "1.0"}}}
    sess = FakeSession({("POST", "/mcp"): FakeResp(200, json.dumps(init),
                        {"Content-Type": "application/json"})})
    det = m._mcp_detect("http://h", sess, 2)
    assert det is not None and det["path"] == "/mcp"
    assert det["init"]["serverInfo"]["name"] == "demo"


def test_mcp_detect_auth_required():
    sess = FakeSession({("POST", "/mcp"): FakeResp(401, "", {"WWW-Authenticate": "Bearer"})})
    det = m._mcp_detect("http://h", sess, 2)
    assert det is not None and det["auth_required"] is True


def test_mcp_detect_version_mismatch_leaks_supported():
    err = {"jsonrpc": "2.0", "id": 1, "error": {"code": -32602, "message": "bad",
           "data": {"supported": ["2024-11-05", "2025-06-18"]}}}
    sess = FakeSession({("POST", "/mcp"): FakeResp(200, json.dumps(err),
                        {"Content-Type": "application/json"})})
    det = m._mcp_detect("http://h", sess, 2)
    assert det is not None and det["supported_versions"] == ["2024-11-05", "2025-06-18"]


def test_mcp_detect_none_for_plain_host():
    sess = FakeSession({("POST", "/mcp"): FakeResp(404, "nope")})
    # all other paths raise (no route) -> overall None
    assert m._mcp_detect("http://h", sess, 1) is None


# --- end-to-end run (network fully mocked) ----------------------------------
def test_extract_model_ids_openai_ollama_and_missing():
    class R:
        def __init__(self, d): self._d = d
        def json(self): return self._d

    # OpenAI /v1/models: has .data, no .models -> must NOT abort, returns ids
    ids = m._extract_model_ids(R({"object": "list", "data": [{"id": "gpt-4o"}, {"id": "gpt-4o-mini"}]}))
    assert "gpt-4o" in ids and "gpt-4o-mini" in ids
    # Ollama /api/tags: name + details.family (the previously-missed path)
    ids2 = m._extract_model_ids(R({"models": [{"name": "llama3", "details": {"family": "llama"}}]}))
    assert "llama3" in ids2 and "llama" in ids2
    # missing keys -> [] (no crash from jq raising on null root)
    assert m._extract_model_ids(R({"foo": "bar"})) == []

    class RB:
        def json(self): raise ValueError("not json")
    assert m._extract_model_ids(RB()) == []


# --- Workload 5: vector-DB confirmation (union of port_scan + http_probe) ----
def test_confirm_vdb_from_port_scan():
    cr = {"port_scan": {"by_host": {"h": {"ip": "1.2.3.4", "ports": [6333]}}},
          "http_probe": {"by_url": {}}}
    routes = {("GET", "/"): FakeResp(200,
              '{"title":"qdrant - vector search engine","version":"1.7"}')}
    out = m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)
    assert len(out) == 1
    assert out[0]["service"] == "qdrant" and out[0]["port"] == 6333
    assert out[0]["ip"] == "1.2.3.4" and out[0]["confirmed_via"] == "read"


def test_confirm_vdb_from_http_probe_fingerprint():
    # chroma sits on shared port 8000 (catalogued ai-runtime), so it can ONLY
    # be confirmed via the http_probe body fingerprint -> ai_framework_name.
    cr = {"port_scan": {"by_host": {}},
          "http_probe": {"by_url": {"http://h:8000/": {
              "is_ai_framework_detected": True, "ai_framework_name": "chroma"}}}}
    routes = {("GET", "/api/v2/heartbeat"): FakeResp(200,
              '{"nanosecond heartbeat": 42}')}
    out = m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)
    assert len(out) == 1 and out[0]["service"] == "chroma" and out[0]["port"] == 8000


def test_confirm_vdb_substring_guard():
    # 200 but the wrong body -> NOT confirmed (qdrant needs 'qdrant'/'result').
    cr = {"port_scan": {"by_host": {"h": {"ip": None, "ports": [6333]}}},
          "http_probe": {"by_url": {}}}
    routes = {("GET", "/"): FakeResp(200, "totally unrelated"),
              ("GET", "/collections"): FakeResp(200, '{"status":"nope"}')}
    out = m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)
    assert out == []


def test_confirm_vdb_dedupes_same_service():
    # same qdrant seen by BOTH sources on the same host:port -> one confirmation.
    cr = {"port_scan": {"by_host": {"h": {"ip": "1.2.3.4", "ports": [6333]}}},
          "http_probe": {"by_url": {"http://h:6333/": {"ai_framework_name": "qdrant"}}}}
    routes = {("GET", "/"): FakeResp(200, '{"title":"qdrant"}')}
    out = m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)
    assert len(out) == 1


def test_confirm_vdb_second_endpoint_wins():
    # first read endpoint 404s, second confirms (multi-endpoint fallback).
    cr = {"port_scan": {"by_host": {"h": {"ip": "1.2.3.4", "ports": [6333]}}},
          "http_probe": {"by_url": {}}}
    routes = {("GET", "/"): FakeResp(404, "nope"),
              ("GET", "/collections"): FakeResp(200, '{"result":{"collections":[]}}')}
    out = m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)
    assert len(out) == 1 and out[0]["service"] == "qdrant"


def test_confirm_vdb_from_http_probe_carries_the_address_httpx_saw():
    # The writer anchors the Technology on this IP (recon audit L-3); without it
    # the only anchor left is the BaseURL.
    cr = {"port_scan": {"by_host": {}},
          "http_probe": {"by_url": {
              "http://vdb.example.com:8000/": {"ai_framework_name": "chroma",
                                               "ip": "203.0.113.5"},
              "http://198.51.100.7:8080/": {"ai_framework_name": "weaviate", "ip": None}}}}
    routes = {("GET", "/api/v2/heartbeat"): FakeResp(200, '{"nanosecond heartbeat": 1}'),
              ("GET", "/v1/meta"): FakeResp(200, '{"modules": {}}')}
    out = {(o["service"], o["host"]): o for o in
           m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)}
    assert out[("chroma", "vdb.example.com")]["ip"] == "203.0.113.5"
    assert out[("weaviate", "198.51.100.7")]["ip"] == "198.51.100.7"


def test_confirm_vdb_fills_a_port_scan_candidate_with_no_ip_from_http_probe():
    cr = {"port_scan": {"by_host": {"vdb.example.com": {"ip": None, "ports": [6333]}}},
          "http_probe": {"by_url": {"http://vdb.example.com:6333/": {
              "ai_framework_name": "qdrant", "ip": "203.0.113.9"}}}}
    routes = {("GET", "/"): FakeResp(200, '{"title":"qdrant"}')}
    out = m._confirm_vector_dbs(cr, FakeSession(routes), timeout=2)
    assert [(o["host"], o["ip"], o["port"]) for o in out] == [
        ("vdb.example.com", "203.0.113.9", 6333)]


def test_run_disabled_returns_early():
    cr = {"metadata": {}}
    out = m.run_ai_surface_recon(cr, settings={"AI_SURFACE_RECON_ENABLED": False})
    assert "ai_surface_recon" not in out


def test_run_empty_graph_is_graceful():
    cr = {"metadata": {"project_id": "p"}, "resource_enum": {"by_base_url": {}},
          "http_probe": {"by_url": {}}, "port_scan": {}}
    out = m.run_ai_surface_recon(cr, settings={"AI_SURFACE_RECON_ENABLED": True,
                                               "AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED": False})
    assert "ai_surface_recon" in out
    assert out["ai_surface_recon"]["summary"]["mcp_servers"] == 0


def test_run_end_to_end_assembles_output(monkeypatch=None):
    cr = {"metadata": {"project_id": "p", "scan_timestamp": "t"},
          "resource_enum": {"by_base_url": {"http://h": {"endpoints": {
              "/v1/chat/completions": {"methods": ["POST"], "ai_interface_type": "llm-chat"}}}}},
          "http_probe": {"by_url": {"http://h/": {"is_ai_framework_detected": True}}},
          "port_scan": {}}
    # stub the network workloads
    orig = (m._probe_chat, m._probe_mcp, m._probe_openapi, m._probe_julius, m._confirm_vector_dbs)
    m._probe_chat = lambda *a, **k: {"path": "/v1/chat/completions", "ai_interface_type": "llm-chat",
                                     "supports_streaming": False, "latency_p50_ms": 12.3}
    m._probe_mcp = lambda *a, **k: {"mcp": {"is_mcp": True, "path": "/mcp", "tool_count": 2,
                                            "server_name": "demo"},
                                    "findings": [m._mk_finding("mcp_tool_poisoning", "high", "x",
                                                 "http://h", "/mcp", "send", "LLM01", "AML.T0051", None)]}
    m._probe_openapi = lambda *a, **k: {"supports_tools": True, "model_family_guess": "gpt"}
    m._probe_julius = lambda *a, **k: {"service": "openai-compatible", "category": "ai-runtime",
                                       "specificity": 1}
    m._confirm_vector_dbs = lambda *a, **k: [{"service": "qdrant", "host": "h", "ip": "1.2.3.4",
                                              "port": 6333, "tech_name": "qdrant", "confirmed_via": "read"}]
    try:
        out = m.run_ai_surface_recon(cr, settings={"AI_SURFACE_RECON_ENABLED": True})
    finally:
        (m._probe_chat, m._probe_mcp, m._probe_openapi, m._probe_julius, m._confirm_vector_dbs) = orig

    asr = out["ai_surface_recon"]
    assert "http://h" in asr["by_url"]
    assert asr["by_url"]["http://h"]["mcp"]["tool_count"] == 2
    assert asr["summary"]["mcp_servers"] == 1
    assert asr["summary"]["chat_endpoints"] == 1
    assert asr["summary"]["mcp_poisoning_findings"] == 1
    assert asr["summary"]["vector_dbs_confirmed"] == 1
    assert "gpt" in asr["summary"]["model_families"]
    assert len(asr["findings"]) == 1 and asr["findings"][0]["id"].startswith("aisr_")


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
