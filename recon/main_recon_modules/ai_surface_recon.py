"""
AI Surface Recon (central module).

The detection/fingerprinting half of the adversarial-AI pipeline. Black-box,
deterministic, recon-side only: it sends benign shape probes, statically
analyzes MCP manifests, parses API specs, runs the Julius fingerprint pack, and
writes property annotations + a few Vulnerability findings. It does NOT
jailbreak, prompt-inject, mutate, or judge.

Runs after resource_enum (display Phase 4.5). Reads:
  - combined_result["resource_enum"]["by_base_url"]  (crawled endpoints, classified)
  - combined_result["http_probe"]["by_url"]          (AI flags, host gate)
  - combined_result["port_scan"]                     (vector-DB candidates)
Writes combined_result["ai_surface_recon"] (consumed by the graph mixin).

Seven workloads (each independently toggled in settings):
  1. Chat-shape probes        -> ai_interface_type, ai_supports_streaming, latency
  2. MCP handshake + tools    -> MCP caps, per-tool Parameters, tool-poisoning Vulns
  3. OpenAPI / manifest parse -> ai_tool_schema_ref, supports_tools/vision, model family
  4. Julius probe pack        -> confirmed Technology(category=ai-*), model family
  5. Vector-DB confirm reads  -> Service -> Technology(ai-vector-db)
  6. Latency p50 baseline     -> ai_latency_p50_ms (piggybacks on #1)
  7. Cross-reference / glue    -> merged interface type, summary counters

All heavy third-party deps (mcp, yara, prance, jq) are imported lazily inside
functions so a not-yet-rebuilt image degrades this module instead of crashing
the whole recon job.
"""

from __future__ import annotations

import json
import time
import hashlib
import asyncio
from pathlib import Path
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

# We probe with verify=False (black-box recon over self-signed/expired TLS);
# silence the per-request InsecureRequestWarning so logs aren't flooded.
try:
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except Exception:
    pass

from recon.helpers import ai_signal_catalog as cat

# Vendored data (Apache-2.0): Cisco MCP YARA rules + Julius probe packs.
# Lives beside the module (the sibling `data/` dir is a root-owned runtime cache).
_DATA_DIR = Path(__file__).parent / "ai_surface_probes"
_YARA_DIR = _DATA_DIR / "yara_rules"
_JULIUS_DIR = _DATA_DIR / "julius"

# OWASP-LLM / MITRE ATLAS mapping for MCP YARA threat types (suggested IDs).
_MCP_THREAT_MAP = {
    "TOOL_POISONING": ("mcp_tool_poisoning", "LLM01", "AML.T0051"),
    "PROMPT_INJECTION": ("mcp_prompt_injection", "LLM01", "AML.T0051"),
    "DATA_EXFILTRATION": ("mcp_data_exfiltration", "LLM06", "AML.T0051"),
    "COMMAND_INJECTION": ("mcp_command_injection", "LLM05", "AML.T0051"),
    "CODE_EXECUTION": ("mcp_code_execution", "LLM05", "AML.T0051"),
    "CREDENTIAL_HARVESTING": ("mcp_credential_harvesting", "LLM06", "AML.T0051"),
}


# --------------------------------------------------------------------------- #
# Logging helpers (standard recon prefix format)
# --------------------------------------------------------------------------- #
def _log(msg: str, sym: str = "*") -> None:
    print(f"[{sym}][AISurfaceRecon] {msg}", flush=True)


# --------------------------------------------------------------------------- #
# Candidate gathering (the §3a identification logic)
# --------------------------------------------------------------------------- #
_CHAT_IFACES = {"llm-chat", "llm-completion", "sse-stream"}


def _host_has_ai_signal(base_url: str, combined_result: dict) -> bool:
    """The §3a gate: does this host already carry an AI fingerprint?"""
    host = urlparse(base_url).hostname or ""
    http = combined_result.get("http_probe", {}).get("by_url", {})
    for url, info in http.items():
        if not isinstance(info, dict):
            continue
        # Match by exact hostname, not substring (avoids http://api.x.com
        # falsely matching http://api.x.com.evil/).
        if host and (urlparse(url).hostname or "") == host:
            if info.get("is_ai_framework_detected") or info.get("ai_framework_name"):
                return True
    # AI-port service on the host
    ps = combined_result.get("port_scan", {}).get("by_host", {})
    hostrec = ps.get(host) if isinstance(ps, dict) else None
    if isinstance(hostrec, dict):
        for p in hostrec.get("ports", []) or []:
            try:
                if cat.lookup_ai_port(int(p)):
                    return True
            except (TypeError, ValueError):
                continue
    return False


def _gather_candidates(combined_result: dict, settings: dict) -> dict:
    """Return {base_url: {host_is_ai, endpoints:[{path,method,iface}]}}."""
    out: dict = {}
    re_data = combined_result.get("resource_enum", {}).get("by_base_url", {}) or {}
    for base_url, base_data in re_data.items():
        if not isinstance(base_data, dict):
            continue
        host_ai = _host_has_ai_signal(base_url, combined_result)
        endpoints = []
        for path, ep in (base_data.get("endpoints") or {}).items():
            if not isinstance(ep, dict):
                continue
            iface = ep.get("ai_interface_type")
            methods = ep.get("methods") or ["GET"]
            if iface in _CHAT_IFACES or iface == "mcp" or host_ai:
                endpoints.append({"path": path, "method": methods[0], "iface": iface})
        if endpoints or host_ai:
            out[base_url] = {"host_is_ai": host_ai, "endpoints": endpoints}
    # Hosts with AI signal but no crawled endpoints: still probe with static paths
    http = combined_result.get("http_probe", {}).get("by_url", {}) or {}
    for url, info in http.items():
        if not isinstance(info, dict):
            continue
        if not (info.get("is_ai_framework_detected") or info.get("ai_framework_name")):
            continue
        parsed = urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        if base not in out:
            out[base] = {"host_is_ai": True, "endpoints": []}
    return out


# --------------------------------------------------------------------------- #
# Workload 1 — chat-shape probes (+ latency baseline)
# --------------------------------------------------------------------------- #
def _probe_chat(base_url: str, cand: dict, session: requests.Session,
                timeout: float, latency_on: bool) -> dict:
    paths = [e["path"] for e in cand["endpoints"] if e.get("iface") in _CHAT_IFACES]
    if not paths and cand["host_is_ai"]:
        paths = list(cat.AI_CHAT_PROBE_PATHS)
    body = json.dumps({"model": "probe",
                       "messages": [{"role": "user", "content": "ping"}],
                       "max_tokens": 1})
    best = None
    latencies = []
    for path in paths[:24]:
        url = base_url.rstrip("/") + path
        t0 = time.monotonic()
        try:
            r = session.post(url, data=body,
                             headers={"Content-Type": "application/json"},
                             timeout=timeout, allow_redirects=False, verify=False)
        except requests.RequestException:
            continue
        latencies.append((time.monotonic() - t0) * 1000.0)
        ctype = r.headers.get("Content-Type", "")
        is_sse = "text/event-stream" in ctype.lower()
        iface = None
        if is_sse:
            # SSE body isn't JSON; classify the first `data:` event, else mark
            # it a streaming endpoint outright.
            iface = cat.classify_ai_chat_response(_first_sse_json(r.text)) or "sse-stream"
        else:
            try:
                iface = cat.classify_ai_chat_response(r.json())
            except ValueError:
                iface = None
        # 401/422 with an OpenAI-style error body still confirms an OpenAI surface
        if iface is None and r.status_code in (401, 422) and '"error"' in (r.text or ""):
            iface = "llm-chat"
        if iface:
            best = {"path": path, "ai_interface_type": iface,
                    "supports_streaming": is_sse}
            break
    result = {}
    if best:
        result.update(best)
    if latency_on and latencies:
        latencies.sort()
        result["latency_p50_ms"] = round(latencies[len(latencies) // 2], 1)
    return result


# --------------------------------------------------------------------------- #
# Workload 2 — MCP handshake + tools/list + static YARA + rug-pull pin
# --------------------------------------------------------------------------- #
def _mcp_detect(base_url: str, session: requests.Session, timeout: float) -> dict | None:
    """Raw POST initialize to detect MCP (capture headers the SDK hides)."""
    init = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
            "params": {"protocolVersion": "2025-06-18",
                       "capabilities": {"roots": {"listChanged": True}, "sampling": {}},
                       "clientInfo": {"name": "RedAmon-AISurfaceRecon", "version": "1.0"}}}
    for path in cat.AI_MCP_PROBE_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = session.post(url, json=init,
                             headers={"Accept": "application/json, text/event-stream"},
                             timeout=timeout, allow_redirects=False, verify=False)
        except requests.RequestException:
            continue
        if r.status_code == 401 and r.headers.get("WWW-Authenticate"):
            return {"path": path, "auth_required": True, "url": url}
        try:
            data = r.json()
        except ValueError:
            # may be an SSE stream; try to read first data: line
            data = _first_sse_json(r.text)
        res = (data or {}).get("result") if isinstance(data, dict) else None
        if isinstance(res, dict) and "protocolVersion" in res and "capabilities" in res \
                and "serverInfo" in res:
            return {"path": path, "auth_required": False, "url": url,
                    "init": res}
        # version-mismatch error leaks supported versions
        err = (data or {}).get("error") if isinstance(data, dict) else None
        if isinstance(err, dict) and isinstance(err.get("data"), dict) \
                and err["data"].get("supported"):
            return {"path": path, "auth_required": False, "url": url,
                    "supported_versions": err["data"]["supported"]}
    return None


def _first_sse_json(text: str) -> dict | None:
    for line in (text or "").splitlines():
        if line.startswith("data:"):
            try:
                return json.loads(line[5:].strip())
            except (ValueError, json.JSONDecodeError):
                return None
    return None


def _mcp_enumerate(url: str, timeout: float) -> dict | None:
    """Use the MCP SDK to list tools/resources/prompts. Async -> own loop."""
    async def _go():
        from mcp import ClientSession
        # The transport export was renamed (streamablehttp_client ->
        # streamable_http_client) and its yielded tuple dropped the session-id
        # callback (3-tuple -> 2-tuple) in a later SDK. Support both.
        try:
            from mcp.client.streamable_http import streamable_http_client as _client
        except ImportError:
            from mcp.client.streamable_http import streamablehttp_client as _client
        async with _client(url) as conn:
            read, write = conn[0], conn[1]  # tolerate 2- or 3-tuple
            async with ClientSession(read, write) as s:
                init = await s.initialize()
                tools = await s.list_tools()
                try:
                    resources = await s.list_resources()
                    res = [r.model_dump(by_alias=True) for r in resources.resources]
                except Exception:
                    res = []
                try:
                    prompts = await s.list_prompts()
                    prm = [p.model_dump(by_alias=True) for p in prompts.prompts]
                except Exception:
                    prm = []
                # Attribute names migrated camelCase -> snake_case across SDK
                # versions; read both. model_dump(by_alias=True) yields camelCase
                # wire keys (inputSchema) on every version.
                si = getattr(init, "serverInfo", None) or getattr(init, "server_info", None)
                return {
                    "server_name": getattr(si, "name", None) if si else None,
                    "server_version": getattr(si, "version", None) if si else None,
                    "protocol_version": (getattr(init, "protocolVersion", None)
                                         or getattr(init, "protocol_version", None)),
                    "instructions": getattr(init, "instructions", None),
                    "tools": [t.model_dump(by_alias=True) for t in tools.tools],
                    "resources": res,
                    "prompts": prm,
                }
    try:
        return asyncio.run(asyncio.wait_for(_go(), timeout * 4))
    except Exception:
        return None


def _yara_scan_text(text: str) -> list:
    """Run vendored MCP YARA rules over one text surface. Failure-soft."""
    rules = _load_yara_rules()
    if rules is None or not text:
        return []
    out = []
    try:
        for m in rules.match(data=text, timeout=20):
            inst = None
            if m.strings and getattr(m.strings[0], "instances", None):
                inst = m.strings[0].instances[0]
            out.append({
                "rule": m.rule,
                "threat_type": (m.meta or {}).get("threat_type"),
                "severity": ((m.meta or {}).get("severity") or "medium").lower(),
                "matched": (inst.matched_data.decode("utf-8", "replace") if inst else None),
                "offset": (inst.offset if inst else None),
            })
    except Exception:
        return []
    return out


_YARA_RULES_CACHE = "__unset__"


def _load_yara_rules():
    global _YARA_RULES_CACHE
    if _YARA_RULES_CACHE != "__unset__":
        return _YARA_RULES_CACHE
    _YARA_RULES_CACHE = None
    if not _YARA_DIR.is_dir():
        return None
    try:
        import yara
        sources = {}
        for fp in sorted(_YARA_DIR.glob("*.y*r*")):
            sources[fp.stem] = fp.read_text(encoding="utf-8")
        if sources:
            _YARA_RULES_CACHE = yara.compile(sources=sources)
    except Exception:
        _YARA_RULES_CACHE = None
    return _YARA_RULES_CACHE


def _tool_hash(tool: dict) -> str:
    payload = {"name": tool.get("name"),
               "description": tool.get("description"),
               "inputSchema": tool.get("inputSchema")}
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
    ).hexdigest()[:32]


def _probe_mcp(base_url: str, session: requests.Session, timeout: float,
               list_tools: bool, yara_on: bool) -> dict | None:
    det = _mcp_detect(base_url, session, timeout)
    if det is None:
        return None
    mcp = {"is_mcp": True, "path": det["path"],
           "auth_required": det.get("auth_required", False),
           "supported_versions": det.get("supported_versions", [])}
    init = det.get("init") or {}
    if init:
        mcp["server_name"] = (init.get("serverInfo") or {}).get("name")
        mcp["server_version"] = (init.get("serverInfo") or {}).get("version")
        mcp["protocol_version"] = init.get("protocolVersion")
        mcp["capabilities"] = list((init.get("capabilities") or {}).keys())
        mcp["instructions"] = init.get("instructions")
    tools_out = []
    findings = []
    if list_tools and not mcp["auth_required"]:
        enum = _mcp_enumerate(det["url"], timeout)
        if enum:
            mcp["server_name"] = enum.get("server_name") or mcp.get("server_name")
            mcp["server_version"] = enum.get("server_version") or mcp.get("server_version")
            mcp["protocol_version"] = enum.get("protocol_version") or mcp.get("protocol_version")
            mcp["instructions"] = enum.get("instructions") or mcp.get("instructions")
            mcp["resource_count"] = len(enum.get("resources") or [])
            mcp["prompt_count"] = len(enum.get("prompts") or [])
            for t in enum.get("tools") or []:
                entry = {"name": t.get("name"), "description": t.get("description"),
                         "input_schema": t.get("inputSchema"),
                         "annotations": t.get("annotations"),
                         "hash": _tool_hash(t)}
                ann = t.get("annotations") or {}
                # Untrusted-annotation contradiction heuristic
                name = (t.get("name") or "").lower()
                mutating = any(k in name for k in ("delete", "write", "exec", "run", "remove", "update"))
                if ann.get("readOnlyHint") and mutating:
                    findings.append(_mk_finding("mcp_annotation_mismatch", "medium",
                                    f"Tool '{t.get('name')}' claims readOnlyHint but name implies mutation",
                                    base_url, det["path"], t.get("name"), "LLM06", "AML.T0051", None))
                if yara_on:
                    surfaces = [t.get("description") or "",
                                json.dumps({k: v for k, v in (t.get("inputSchema") or {}).items()})]
                    for surf in surfaces:
                        for y in _yara_scan_text(surf):
                            kind, owasp, atlas = _MCP_THREAT_MAP.get(
                                (y.get("threat_type") or "").upper(),
                                ("mcp_tool_poisoning", "LLM01", "AML.T0051"))
                            findings.append(_mk_finding(
                                kind, y["severity"],
                                f"MCP tool '{t.get('name')}': {y['rule']}",
                                base_url, det["path"], t.get("name"),
                                owasp, atlas,
                                json.dumps({"matched": y.get("matched"), "offset": y.get("offset")})))
                tools_out.append(entry)
            # server-instructions YARA
            if yara_on and mcp.get("instructions"):
                for y in _yara_scan_text(mcp["instructions"]):
                    findings.append(_mk_finding("mcp_prompt_injection", y["severity"],
                                    f"MCP server instructions: {y['rule']}",
                                    base_url, det["path"], None, "LLM01", "AML.T0051",
                                    json.dumps({"matched": y.get("matched")})))
            mcp["tools"] = tools_out
            mcp["tool_count"] = len(tools_out)
            mcp["tools_hash"] = hashlib.sha256(
                "".join(sorted(t["hash"] for t in tools_out)).encode()).hexdigest()[:32]
            if mcp.get("instructions"):
                mcp["instructions_hash"] = hashlib.sha256(
                    mcp["instructions"].encode()).hexdigest()[:32]
    return {"mcp": mcp, "findings": findings}


def _mk_finding(ftype, severity, desc, base_url, path, tool, owasp, atlas, evidence):
    fid = "aisr_" + hashlib.sha256(
        f"{ftype}|{base_url}|{path}|{tool}".encode()).hexdigest()[:16]
    return {"id": fid, "type": ftype, "severity": severity, "name": desc,
            "baseurl": base_url, "path": path, "tool_name": tool,
            "owasp_llm_id": owasp, "atlas_technique": atlas, "evidence": evidence}


# --------------------------------------------------------------------------- #
# Workload 3 — OpenAPI / ai-plugin.json / model-listing
# --------------------------------------------------------------------------- #
def _probe_openapi(base_url: str, session: requests.Session, timeout: float,
                   model_list_on: bool, specs_dir: Path) -> dict:
    out = {}
    model_ids = []
    for path in cat.AI_OPENAPI_DISCOVERY_PATHS:
        url = base_url.rstrip("/") + path
        try:
            r = session.get(url, timeout=timeout, allow_redirects=False, verify=False)
        except requests.RequestException:
            continue
        if r.status_code != 200:
            continue
        if path in ("/v1/models", "/models", "/api/tags"):
            if model_list_on:
                model_ids.extend(_extract_model_ids(r))
            continue
        # OpenAPI / ai-plugin spec
        parsed = _parse_spec(r.text)
        if parsed:
            out.update(parsed)
            ref = _cache_spec(parsed.get("_spec"), base_url, path, specs_dir)
            if ref:
                out["tool_schema_ref"] = ref
            out.pop("_spec", None)
    fam = cat.guess_model_family(model_ids)
    if fam:
        out["model_family_guess"] = fam
    if model_ids:
        out["model_ids"] = model_ids[:50]
    return out


def _extract_model_ids(resp) -> list:
    try:
        data = resp.json()
    except ValueError:
        return []
    ids: list = []
    # jq path: run each expression independently — jq RAISES (not []) when a
    # path root is missing (e.g. .models on an OpenAI /v1/models response), so
    # one failing expression must not abort the others.
    try:
        import jq
        for expr in (".data[].id", ".models[].name", ".models[].details.family"):
            try:
                ids += [x for x in jq.compile(expr).input_value(data).all()
                        if isinstance(x, str)]
            except Exception:
                continue
        if ids:
            return ids
    except Exception:
        pass
    # plain-python fallback (also covers Ollama details.family)
    if isinstance(data, dict):
        for m in data.get("data") or []:
            if isinstance(m, dict) and m.get("id"):
                ids.append(m["id"])
        for m in data.get("models") or []:
            if isinstance(m, dict):
                if m.get("name"):
                    ids.append(m["name"])
                fam = (m.get("details") or {}).get("family")
                if fam:
                    ids.append(fam)
    return [x for x in ids if isinstance(x, str)]


def _parse_spec(text: str) -> dict | None:
    try:
        doc = json.loads(text)
    except (ValueError, json.JSONDecodeError):
        return None
    # ai-plugin.json manifest
    if isinstance(doc, dict) and doc.get("schema_version") and doc.get("api"):
        return {"supports_tools": True, "_spec": doc,
                "manifest_name": doc.get("name_for_model")}
    # OpenAPI: resolve with prance if available
    spec = doc
    try:
        from prance import ResolvingParser
        spec = ResolvingParser(spec_string=text, backend="openapi-spec-validator").specification
    except Exception:
        spec = doc
    info = {"_spec": spec}
    blob = json.dumps(spec).lower()
    if '"tools"' in blob or '"function"' in blob or '"input_schema"' in blob:
        info["supports_tools"] = True
    if '"image_url"' in blob or '"image"' in blob:
        info["supports_vision"] = True
    if '"stream"' in blob or "text/event-stream" in blob:
        info["supports_streaming"] = True
    return info if len(info) > 1 else None


def _cache_spec(spec, base_url, path, specs_dir: Path) -> str | None:
    if spec is None:
        return None
    try:
        specs_dir.mkdir(parents=True, exist_ok=True)
        h = hashlib.sha256(f"{base_url}{path}".encode()).hexdigest()[:16]
        fp = specs_dir / f"{h}.json"
        fp.write_text(json.dumps(spec, default=str), encoding="utf-8")
        return str(fp)
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# Workload 4 — Julius probe pack
# --------------------------------------------------------------------------- #
def _probe_julius(base_url: str, timeout: float, ua: str) -> dict:
    from recon.helpers.probe_pack_engine import load_probe_packs, run_probe_packs
    probes = load_probe_packs(_JULIUS_DIR)
    if not probes:
        return {}
    parsed = urlparse(base_url)
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    results = run_probe_packs(base_url, probes, target_port=port,
                              timeout=timeout, user_agent=ua)
    if not results:
        return {}
    top = results[0]
    out = {"service": top.name, "category": top.category,
           "specificity": top.specificity}
    if top.model_ids:
        fam = cat.guess_model_family(top.model_ids)
        if fam:
            out["model_family_guess"] = fam
        out["model_ids"] = top.model_ids[:50]
    return out


# --------------------------------------------------------------------------- #
# Workload 5 — vector-DB confirmation reads
# --------------------------------------------------------------------------- #
def _confirm_vector_dbs(combined_result: dict, session: requests.Session,
                        timeout: float) -> list:
    """Confirm vector DBs via a benign unauthenticated read.

    Candidates are unioned from two sources, then deduped on (tech, host, port):
      1. port_scan — open ports whose AI_PORTS entry is an ``ai-vector-db`` with
         a known read recipe (e.g. qdrant:6333, milvus:19530).
      2. http_probe — hosts whose body/title fingerprint set ``ai_framework_name``
         to a known vector DB. This is the ONLY way DBs on shared ports
         (chroma:8000 = ai-runtime, weaviate:8080 = ai-frontend) get confirmed.

    Each candidate is then read-confirmed against AI_VECTOR_DB_READS[tech]: the
    first endpoint that returns 200 (+ optional expected substring) wins.
    """
    out = []
    # (tech, host, port) -> {"ip": str|None, "schemes": tuple}
    candidates: dict = {}

    ps = combined_result.get("port_scan", {}).get("by_host", {}) or {}
    for host, rec in ps.items():
        if not isinstance(rec, dict):
            continue
        ip = rec.get("ip")
        for p in rec.get("ports", []) or []:
            try:
                port = int(p)
                meta = cat.lookup_ai_port(port)
            except (TypeError, ValueError):
                continue
            if not meta or meta.get("category") != "ai-vector-db":
                continue
            tech = meta.get("name")
            if tech not in cat.AI_VECTOR_DB_READS:
                continue
            candidates.setdefault((tech, host, port),
                                  {"ip": ip, "schemes": ("http", "https")})

    http = combined_result.get("http_probe", {}).get("by_url", {}) or {}
    for url, info in http.items():
        if not isinstance(info, dict):
            continue
        tech = info.get("ai_framework_name")
        if tech not in cat.AI_VECTOR_DB_READS:
            continue
        parsed = urlparse(url)
        host = parsed.hostname
        if not host:
            continue
        try:
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
        except ValueError:
            continue
        other = "https" if parsed.scheme == "http" else "http"
        candidates.setdefault((tech, host, int(port)),
                              {"ip": None, "schemes": (parsed.scheme or "http", other)})

    for (tech, host, port), info in candidates.items():
        reads = cat.AI_VECTOR_DB_READS.get(tech) or []
        confirmed = False
        for scheme in info["schemes"]:
            if confirmed:
                break
            for path, expect in reads:
                url = f"{scheme}://{host}:{port}{path}"
                try:
                    r = session.get(url, timeout=timeout, verify=False,
                                    allow_redirects=False)
                except requests.RequestException:
                    continue
                if r.status_code == 200 and (not expect or expect in (r.text or "")):
                    out.append({"service": tech, "host": host, "ip": info["ip"],
                                "port": port, "tech_name": tech, "confirmed_via": "read"})
                    confirmed = True
                    break
    return out


# --------------------------------------------------------------------------- #
# Entry point
# --------------------------------------------------------------------------- #
def run_ai_surface_recon(combined_result: dict, output_file: Path = None,
                         settings: dict = None) -> dict:
    print("\n[*][AISurfaceRecon] [Phase 4.5] AI Surface Recon")
    if settings is None:
        settings = {}
    if not settings.get("AI_SURFACE_RECON_ENABLED", True):
        _log("disabled — skipping", "-")
        return combined_result

    # RoE time window (lazy import to avoid circular import with main.py)
    try:
        from recon.main import _check_roe_time_window
        allowed, reason = _check_roe_time_window(settings)
        if not allowed:
            _log(f"blocked by RoE time window: {reason}", "!")
            return combined_result
    except Exception:
        pass

    t0 = time.monotonic()
    timeout = float(settings.get("AI_SURFACE_RECON_TIMEOUT", 10))
    workers = int(settings.get("AI_SURFACE_RECON_MAX_WORKERS", 5))
    ua = settings.get("AI_SURFACE_RECON_USER_AGENT", "RedAmon-AISurfaceRecon/1.0")
    chat_on = settings.get("AI_SURFACE_RECON_CHAT_SHAPE_PROBE_ENABLED", True)
    mcp_on = settings.get("AI_SURFACE_RECON_MCP_HANDSHAKE_ENABLED", True)
    mcp_list_on = settings.get("AI_SURFACE_RECON_MCP_LIST_TOOLS_ENABLED", True)
    yara_on = settings.get("AI_SURFACE_RECON_MCP_YARA_ENABLED", True)
    openapi_on = settings.get("AI_SURFACE_RECON_OPENAPI_DISCOVERY_ENABLED", True)
    model_list_on = settings.get("AI_SURFACE_RECON_MODEL_LIST_ENABLED", True)
    vectordb_on = settings.get("AI_SURFACE_RECON_VECTOR_DB_READ_ENABLED", True)
    julius_on = settings.get("AI_SURFACE_RECON_JULIUS_PROBE_PACK_ENABLED", True)
    latency_on = settings.get("AI_SURFACE_RECON_LATENCY_BASELINE_ENABLED", True)

    candidates = _gather_candidates(combined_result, settings)
    # RoE host exclusion
    try:
        from recon.helpers.roe_scope import _filter_roe_excluded
        hosts = list(candidates.keys())
        kept = set(_filter_roe_excluded(hosts, settings, label="ai-surface url"))
        candidates = {k: v for k, v in candidates.items() if k in kept}
    except Exception:
        pass

    _log(f"analyzing {len(candidates)} AI-surface host(s)")
    project_id = combined_result.get("metadata", {}).get("project_id", "unknown")
    specs_dir = Path("/tmp/redamon") / "ai_surface_recon" / str(project_id) / "specs"

    by_url: dict = {}
    findings: list = []

    def _analyze(base_url: str, cand: dict) -> tuple:
        session = requests.Session()
        session.headers.update({"User-Agent": ua})
        # Authenticated-session profile: attach the operator's auth headers when
        # this base_url is in scope (no-op otherwise). AI endpoints frequently sit
        # behind login; without this they answer 401 and look absent.
        try:
            from recon.helpers.auth_profile import auth_header_lines as _auth_lines
            _host = urlparse(base_url).hostname or ""
            for _line in _auth_lines(settings.get("AUTH_PROFILE"), _host, settings):
                _name, _val = _line.split(":", 1)
                session.headers[_name.strip()] = _val.strip()
        except Exception:
            pass
        rec: dict = {}
        local_findings: list = []
        try:
            if chat_on:
                chat = _probe_chat(base_url, cand, session, timeout, latency_on)
                if chat:
                    rec["chat"] = chat
            if mcp_on:
                mcp_res = _probe_mcp(base_url, session, timeout, mcp_list_on, yara_on)
                if mcp_res:
                    rec["mcp"] = mcp_res["mcp"]
                    local_findings.extend(mcp_res["findings"])
            if openapi_on:
                oa = _probe_openapi(base_url, session, timeout, model_list_on, specs_dir)
                if oa:
                    rec["openapi"] = oa
            if julius_on:
                jl = _probe_julius(base_url, timeout, ua)
                if jl:
                    rec["julius"] = jl
        except Exception as e:
            _log(f"{base_url}: {e}", "!")
        return base_url, rec, local_findings

    if candidates:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            futs = [ex.submit(_analyze, b, c) for b, c in candidates.items()]
            for f in as_completed(futs):
                base_url, rec, lf = f.result()
                if rec:
                    by_url[base_url] = rec
                findings.extend(lf)

    vector_db = []
    if vectordb_on:
        vsession = requests.Session()
        vsession.headers.update({"User-Agent": ua})
        vector_db = _confirm_vector_dbs(combined_result, vsession, timeout)

    summary = {
        "mcp_servers": sum(1 for r in by_url.values() if r.get("mcp")),
        "mcp_tools_total": sum(len(r.get("mcp", {}).get("tools", [])) for r in by_url.values()),
        "mcp_poisoning_findings": len(findings),
        "chat_endpoints": sum(1 for r in by_url.values() if r.get("chat", {}).get("ai_interface_type")),
        "tool_call_endpoints": sum(1 for r in by_url.values() if r.get("openapi", {}).get("supports_tools")),
        "vector_dbs_confirmed": len(vector_db),
        "model_families": sorted({r.get("chat", {}).get("model_family_guess")
                                  or r.get("openapi", {}).get("model_family_guess")
                                  or r.get("julius", {}).get("model_family_guess")
                                  for r in by_url.values()} - {None}),
    }
    combined_result["ai_surface_recon"] = {
        "scan_metadata": {
            "scan_timestamp": combined_result.get("metadata", {}).get("scan_timestamp"),
            "duration_s": round(time.monotonic() - t0, 1),
            "hosts_analyzed": len(candidates),
            "probe_pack_version": settings.get("AI_SURFACE_RECON_PROBE_PACK_VERSION", "latest"),
        },
        "by_url": by_url,
        "vector_db": vector_db,
        "findings": findings,
        "summary": summary,
    }
    _log(f"done in {round(time.monotonic() - t0, 1)}s — "
         f"{summary['mcp_servers']} MCP, {summary['chat_endpoints']} chat, "
         f"{summary['vector_dbs_confirmed']} vector-db, {len(findings)} findings", "+")

    if output_file:
        try:
            with open(output_file, "w") as fh:
                json.dump(combined_result, fh, indent=2, default=str)
        except Exception:
            pass
    return combined_result
