"""AI Surface never fetches or reads a `$ref` of a target's OpenAPI document (S-8).

_probe_openapi hands the body a target serves at /openapi.json (and the other
discovery paths) to _parse_spec. A resolving parser (prance) follows every
`$ref`: an `http://...` one is fetched from inside the recon container (no
RoE, no rate ceiling, no SSRF guard) and a `file://` one is read from its
disk, both inlined into the spec _cache_spec writes under /tmp/redamon and
read for the capability flags. Only `#/...` pointers into the served
document may be inlined, with no I/O and within a budget.

A loopback HTTP server records every request; the local file is a temp file.
"""
from __future__ import annotations

import http.server
import json
import sys
import threading
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import pytest  # noqa: E402

from recon.main_recon_modules import ai_surface_recon as m  # noqa: E402
from recon.main_recon_modules.ai_surface_recon import _parse_spec  # noqa: E402


@pytest.fixture
def remote():
    hits = []

    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            hits.append(self.path)
            body = json.dumps({"type": "object",
                               "properties": {"tools": {"type": "string"}}}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = http.server.HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, kwargs={"poll_interval": 0.02},
                     daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", hits
    srv.shutdown()


def _op(ref: str) -> dict:
    return {"get": {"responses": {"200": {"description": "ok", "content": {
        "application/json": {"schema": {"$ref": ref}}}}}}}


def _doc(**paths) -> dict:
    return {"openapi": "3.0.0", "info": {"title": "t", "version": "1"},
            "paths": {f"/{k}": _op(v) for k, v in paths.items()}}


def _spec(**paths) -> str:
    return json.dumps(_doc(**paths))


def _schema(spec: dict, path: str) -> dict:
    return spec["paths"][path]["get"]["responses"]["200"]["content"]["application/json"]["schema"]


def test_a_remote_ref_is_never_fetched(remote):
    base, hits = remote
    ref = f"{base}/internal/schema.json"
    info = _parse_spec(_spec(chat=ref))
    assert hits == [], f"the recon container fetched {hits} for the target's $ref"
    assert not (info or {}).get("supports_tools"), "a capability was read off a fetched document"


def test_a_file_ref_is_never_read(tmp_path):
    local = tmp_path / "local.json"
    local.write_text(json.dumps({"type": "object", "properties": {
        "stream": {"type": "string"}, "marker_from_local_disk": {"type": "string"}}}))
    info = _parse_spec(_spec(stream=f"file://{local}"))
    assert "marker_from_local_disk" not in json.dumps((info or {}).get("_spec")), \
        "a local file was inlined into the cached spec"
    assert not (info or {}).get("supports_streaming")


@pytest.mark.parametrize("ref", [
    "{base}/internal/schema.json#/Thing",
    "//127.0.0.1:{port}/internal/schema.json",
    "internal/schema.json",
    "/internal/schema.json#/Thing",
    "file:///etc/hostname",
])
def test_an_external_ref_stays_as_data(remote, ref):
    """Absolute, scheme-relative and relative refs are kept verbatim, never fetched."""
    base, hits = remote
    ref = ref.format(base=base, port=base.rsplit(":", 1)[1])
    doc = _doc(chat=ref)
    doc["components"] = {"schemas": {"Thing": {"properties": {"stream": {"type": "boolean"}}}}}
    info = _parse_spec(json.dumps(doc))
    assert hits == []
    assert info["supports_streaming"]
    assert _schema(info["_spec"], "/chat") == {"$ref": ref}


def test_what_the_target_served_is_still_read(remote):
    """A capability in the document itself, behind an internal $ref, is found
    and the ref is inlined in the cached spec, as before."""
    base, hits = remote
    doc = _doc(chat="#/components/schemas/Call")
    doc["components"] = {"schemas": {"Call": {"type": "object", "properties": {
        "tools": {"type": "array"}}}}}
    info = _parse_spec(json.dumps(doc))
    assert info and info.get("supports_tools")
    assert _schema(info["_spec"], "/chat") == doc["components"]["schemas"]["Call"]
    assert hits == []


def test_pointer_escapes_and_percent_encoding_resolve():
    doc = _doc(a="#/components/schemas/a~1b", b="#/components/schemas/with%20space",
               c="#/components/schemas/t~0x", d="#/components/list/1")
    doc["components"] = {"schemas": {"a/b": {"title": "slash"}, "with space": {"title": "space"},
                                     "t~x": {"title": "tilde"}},
                         "list": [{"title": "zero"}, {"title": "one"}]}
    spec = m._resolve_local_refs(doc)
    assert [_schema(spec, p)["title"] for p in ("/a", "/b", "/c", "/d")] == \
        ["slash", "space", "tilde", "one"]


def test_a_pointer_to_nothing_stays_as_data():
    doc = _doc(a="#/components/schemas/Missing", b="#/components/list/x", c="#anchor")
    doc["components"] = {"schemas": {}, "list": [{}]}
    spec = m._resolve_local_refs(doc)
    assert [_schema(spec, p) for p in ("/a", "/b", "/c")] == [
        {"$ref": "#/components/schemas/Missing"}, {"$ref": "#/components/list/x"},
        {"$ref": "#anchor"}]


def test_a_cyclic_ref_stays_as_data_and_the_rest_resolves():
    doc = _doc(node="#/components/schemas/Node")
    doc["components"] = {"schemas": {"Node": {"type": "object", "properties": {
        "next": {"$ref": "#/components/schemas/Node"}, "tools": {"type": "array"}}}}}
    info = _parse_spec(json.dumps(doc))
    node = _schema(info["_spec"], "/node")
    assert node["properties"]["tools"] == {"type": "array"}
    assert node["properties"]["next"] == {"$ref": "#/components/schemas/Node"}
    assert info.get("supports_tools")


def test_a_self_ref_to_the_whole_document_terminates():
    doc = {"openapi": "3.0.0", "x": {"$ref": "#"}}
    spec = m._resolve_local_refs(doc)
    assert spec["x"]["x"] == {"$ref": "#"}


def test_alias_fan_out_is_bounded_and_falls_back_to_the_served_document():
    """Ten levels that each reference the one below ten times would expand to
    10**10 nodes; over the budget the served document is cached unresolved."""
    schemas = {"L0": {"type": "string", "description": "x" * 64}}
    for i in range(1, 11):
        schemas[f"L{i}"] = {"type": "array",
                            "items": [{"$ref": f"#/components/schemas/L{i - 1}"}] * 10}
    doc = _doc(bomb="#/components/schemas/L10")
    doc["components"] = {"schemas": schemas}
    doc["x-capabilities"] = {"stream": True}
    started = time.monotonic()
    info = _parse_spec(json.dumps(doc))
    assert time.monotonic() - started < 10
    assert info["_spec"] == doc
    assert info["supports_streaming"]


def test_a_huge_string_referenced_many_times_hits_the_character_budget(monkeypatch):
    monkeypatch.setattr(m, "_SPEC_REF_MAX_CHARS", 10_000)
    doc = _doc(**{f"p{i}": "#/components/schemas/Big" for i in range(20)})
    doc["components"] = {"schemas": {"Big": {"description": "y" * 1_000}}}
    assert m._resolve_local_refs(doc) is doc


def test_probe_openapi_sends_only_the_discovery_paths_and_caches_no_fetched_content(
        remote, tmp_path, monkeypatch):
    """The whole workload: the only requests are the discovery GETs on the
    target's session, and the cached spec holds the external ref as data."""
    base, hits = remote
    served = _doc(chat=f"{base}/internal/schema.json")
    served["components"] = {"schemas": {"Event": {"properties": {"stream": {"type": "boolean"}}}}}
    calls = []

    class Resp:
        def __init__(self, status, text=""):
            self.status_code = status
            self.text = text

        def json(self):
            return json.loads(self.text)

    class Session:
        def get(self, url, **kw):
            calls.append(url)
            return Resp(200, json.dumps(served)) if url.endswith("/openapi.json") else Resp(404)

    monkeypatch.setattr(m.cat, "AI_OPENAPI_DISCOVERY_PATHS", ["/openapi.json", "/swagger.json"])
    out = m._probe_openapi("http://203.0.113.10", Session(), 5, True, tmp_path / "specs")
    assert calls == ["http://203.0.113.10/openapi.json", "http://203.0.113.10/swagger.json"]
    assert hits == []
    assert out["supports_streaming"] and "supports_tools" not in out
    cached = json.loads(Path(out["tool_schema_ref"]).read_text())
    assert _schema(cached, "/chat") == {"$ref": f"{base}/internal/schema.json"}
