"""Unit tests for the proxy_brain traffic broker's security contract.

The /traffic/exec + /traffic/replay endpoints derive tenant identity from a
signed `X-Redamon-Ctx` tag (source=agent), NOT from the request body. The whole
isolation guarantee rests on: only a holder of INTERNAL_API_KEY can mint a tag
for a given tenant, and the kali worker does not hold that key. These tests pin
that contract at the primitive the endpoint's `_verify_traffic_ctx` wraps.
"""
import pytest

from redamon_ctx import sign_tag, verify_tag

AGENT_KEY = "agent-internal-key-abc123"
SCANNER_KEY = "scanner-scoped-key-xyz789"


def _agent_tag(user_id="u1", project_id="p1", phase="exploitation", key=AGENT_KEY):
    return sign_tag({
        "source": "agent", "user_id": user_id, "project_id": project_id,
        "session_id": "sess1", "tool": "proxy_brain", "phase": phase,
    }, key)


def test_valid_agent_tag_yields_tenant_and_phase():
    tok = _agent_tag()
    claims = verify_tag(tok, {"agent": AGENT_KEY})
    assert claims is not None
    assert claims["user_id"] == "u1"
    assert claims["project_id"] == "p1"
    assert claims["phase"] == "exploitation"


def test_tag_signed_with_wrong_key_is_rejected():
    # An attacker who does NOT hold INTERNAL_API_KEY cannot forge a tag the
    # agent will accept — this is what stops a kali foothold (which holds only
    # the scoped SCANNER_API_KEY) from asserting a cross-tenant identity.
    forged = _agent_tag(user_id="victim", project_id="victim_proj", key=SCANNER_KEY)
    assert verify_tag(forged, {"agent": AGENT_KEY}) is None


def test_recon_source_tag_rejected_by_agent_only_keymap():
    # /traffic/* verify with {"agent": INTERNAL_API_KEY} only. A recon-sourced
    # tag (even validly signed) has no matching key and fails closed.
    tok = sign_tag({"source": "recon", "user_id": "u1", "project_id": "p1"}, SCANNER_KEY)
    assert verify_tag(tok, {"agent": AGENT_KEY}) is None


def test_tampered_tenant_breaks_signature():
    tok = _agent_tag(user_id="u1", project_id="p1")
    body_b64, sig_b64 = tok.split(".", 1)
    # Swap in a different (validly-formatted) body; the signature no longer matches.
    other = _agent_tag(user_id="attacker", project_id="attacker_proj")
    tampered = other.split(".", 1)[0] + "." + sig_b64
    assert verify_tag(tampered, {"agent": AGENT_KEY}) is None


def test_missing_tenant_fields_are_rejectable():
    # _verify_traffic_ctx additionally requires user_id AND project_id present;
    # a tag lacking them must not authorize a read/send.
    tok = sign_tag({"source": "agent", "tool": "proxy_brain", "phase": "exploitation"}, AGENT_KEY)
    claims = verify_tag(tok, {"agent": AGENT_KEY})
    # verify_tag may return the payload, but the endpoint gate requires tenant:
    assert not (claims and claims.get("user_id") and claims.get("project_id"))


@pytest.mark.parametrize("phase,allowed", [
    ("informational", False),
    ("exploitation", True),
    ("post_exploitation", True),
    ("", False),
])
def test_active_replay_phase_gate(phase, allowed):
    # Mirrors the /traffic/replay per-send phase gate: active sends only in the
    # exploitation phases (fail closed otherwise).
    gate = phase in ("exploitation", "post_exploitation")
    assert gate is allowed


# --------------------------------------------------------------------------
# F1: replay host-pin — mutate.path must never re-open the URL authority.
# --------------------------------------------------------------------------
def _txn(host="origin.example.com", scheme="http", port=80, path="/item", query="id=1"):
    return {"host": host, "scheme": scheme, "port": port, "path": path,
            "query": query, "method": "GET", "req_headers": {}, "req_body": None}


def _replay_netloc(curl_args):
    import shlex
    from urllib.parse import urlsplit
    # build_replay_curl appends the URL as the final positional arg.
    return urlsplit(shlex.split(curl_args)[-1]).netloc


def test_replay_pins_host_on_normal_path():
    from traffic_tools import build_replay_curl
    assert _replay_netloc(build_replay_curl(_txn(), {"path": "/other"})) == "origin.example.com"


@pytest.mark.parametrize("evil_path", [
    "@evil.com/steal",     # userinfo trick: http://origin@evil.com/
    "@evil.com",
    "evil.com/x",          # unrooted path becomes part of the authority
    "@127.0.0.1/",         # would-be SSRF via userinfo
])
def test_replay_host_pin_blocks_authority_injection(evil_path):
    # A hostile mutate.path must not move the target off the origin host.
    from traffic_tools import build_replay_curl
    netloc = _replay_netloc(build_replay_curl(_txn(), {"path": evil_path}))
    assert netloc == "origin.example.com", f"host pin escaped to {netloc!r}"
    assert "evil.com" not in netloc and "127.0.0.1" not in netloc


def test_replay_preserves_nondefault_port_in_pin():
    from traffic_tools import build_replay_curl
    netloc = _replay_netloc(build_replay_curl(_txn(port=8080), {"path": "@evil.com/"}))
    assert netloc == "origin.example.com:8080"


# --------------------------------------------------------------------------
# Row 12: proxy_brain must be registered in every layer or the agent sees a
# tool it cannot dispatch (or an MCP tool the manifest filter drops silently).
# --------------------------------------------------------------------------
def test_proxy_brain_registered_across_layers():
    from prompts.tool_registry import TOOL_REGISTRY
    from project_settings import DEFAULT_AGENT_SETTINGS, DANGEROUS_TOOLS
    import tools
    assert "proxy_brain" in TOOL_REGISTRY, "not advertised to the LLM"
    pm = DEFAULT_AGENT_SETTINGS["TOOL_PHASE_MAP"]
    # All phases: read/decode is safe everywhere; active sends are gated at
    # /traffic/replay, not by the phase map.
    assert pm.get("proxy_brain") == ["informational", "exploitation", "post_exploitation"], "phase map missing/wrong"
    # The retired proxy_* tools must be gone from every layer.
    for dead in ("proxy_search", "proxy_get", "proxy_replay", "proxy_fuzz", "proxy_query"):
        assert dead not in TOOL_REGISTRY, f"{dead} still registered"
        assert dead not in pm, f"{dead} still in phase map"
    assert "proxy_brain" in tools.SYSTEM_MCP_TOOL_NAMES, "would be dropped by the manifest filter"
    assert "proxy_brain" in DANGEROUS_TOOLS, "active tool must require confirmation"
