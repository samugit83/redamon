#!/usr/bin/env python3
"""Tests for the orchestrator API authentication (V1-auth).

Part A - pure unit tests of the security decision (auth.is_orchestrator_request_
authorized). No FastAPI, no docker, no network. This is the security-critical
core: it decides which requests reach the Docker-socket holder.

Part B - exploit reproduction against a minimal ASGI app: the same routes
WITHOUT the middleware (pre-patch: unauth request succeeds = the vulnerability)
vs. WITH the real middleware (post-patch: unauth = 401, /health exempt, valid
key = 200). Part B self-skips when fastapi is unavailable.
"""
import asyncio
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import auth  # noqa: E402

KEY = "s3cret-orchestrator-key-0123456789abcdef"


def authorized(path, method, presented, expected=KEY):
    return auth.is_orchestrator_request_authorized(path, method, presented, expected)


# --------------------------------------------------------------------------
# Part A: the auth decision
# --------------------------------------------------------------------------

@pytest.mark.parametrize("path,method", [
    ("/recon/running", "GET"),
    ("/recon/x/start", "POST"),
    ("/defaults", "GET"),
])
def test_legitimate_webapp_call_with_correct_key_allowed(path, method):
    assert authorized(path, method, KEY) is True


@pytest.mark.parametrize("desc,path,method,presented", [
    ("no key, list running", "/recon/running", "GET", ""),
    ("no key, start recon", "/recon/x/start", "POST", ""),
    ("no key, start ai-attack-surface", "/ai-attack-surface/x/start", "POST", ""),
    ("no key, delete data", "/recon/x/data", "DELETE", ""),
    ("wrong key", "/recon/running", "GET", "wrong-key"),
    ("trailing space", "/recon/running", "GET", KEY + " "),
    ("one char off", "/recon/running", "GET", KEY[:-1] + "X"),
    ("prefix of the key", "/recon/running", "GET", KEY[:10]),
])
def test_unauthenticated_or_wrong_key_denied(desc, path, method, presented):
    assert authorized(path, method, presented) is False


@pytest.mark.parametrize("method", ["GET", "HEAD"])
def test_health_is_exempt_without_a_key(method):
    """The Docker healthcheck polls /health unauthenticated."""
    assert authorized("/health", method, "") is True


def test_cors_preflight_is_exempt():
    assert authorized("/recon/x/start", "OPTIONS", "") is True


@pytest.mark.parametrize("presented", ["", "anything"])
def test_fail_closed_when_no_key_is_configured(presented):
    assert authorized("/recon/running", "GET", presented, expected="") is False


def test_health_stays_exempt_when_no_key_is_configured():
    assert authorized("/health", "GET", "", expected="") is True


@pytest.mark.parametrize("path,method", [
    ("/health/", "GET"),
    ("/health/../recon/running", "GET"),
    ("/HEALTH", "GET"),
    ("/health/x", "GET"),
    ("//health", "GET"),
    ("/healthz", "GET"),
    ("/health2", "GET"),
    ("/health/../local-llm/ensure", "POST"),
])
def test_no_protected_route_may_masquerade_as_health(path, method):
    """Exact-match exemption: nothing /health-ish is a free pass."""
    assert authorized(path, method, "") is False


# --------------------------------------------------------------------------
# Part B: exploit reproduction, pre-patch vs post-patch
# --------------------------------------------------------------------------

@pytest.fixture(scope="module")
def apps():
    """(pre_patch, post_patch): identical routes, only the middleware differs,
    so the exploit and its fix are asserted against one harness."""
    pytest.importorskip("fastapi", reason="Part B needs fastapi (orchestrator image has it)")
    from fastapi import FastAPI, Request
    from fastapi.responses import JSONResponse

    def build(with_auth: bool):
        app = FastAPI()

        if with_auth:
            @app.middleware("http")
            async def mw(request: Request, call_next):
                if auth.is_orchestrator_request_authorized(
                    request.url.path, request.method,
                    request.headers.get("X-Orchestrator-Key", ""), KEY,
                ):
                    return await call_next(request)
                return JSONResponse(status_code=401, content={"detail": "Unauthorized"})

        @app.get("/health")
        async def health():
            return {"status": "healthy"}

        @app.post("/recon/{pid}/start")
        async def start(pid: str):
            # Stand-in for "spawn a container / drive the privileged orchestrator".
            return {"started": pid}

        return app

    return build(with_auth=False), build(with_auth=True)


def status(app, method, path, headers=None):
    """Drive an ASGI app directly (no httpx). Returns the HTTP status code.

    Uses a private loop rather than asyncio.run so the process-wide current
    loop is never cleared for whatever test runs next.
    """
    hdrs = [(k.lower().encode(), v.encode()) for k, v in (headers or {}).items()]
    scope = {
        "type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1",
        "method": method, "path": path, "raw_path": path.encode(),
        "query_string": b"", "headers": hdrs, "client": ("127.0.0.1", 12345),
        "server": ("127.0.0.1", 8010), "scheme": "http",
    }
    state = {"status": None}

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(msg):
        if msg["type"] == "http.response.start":
            state["status"] = msg["status"]

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(app(scope, receive, send))
    finally:
        loop.close()
    return state["status"]


def test_pre_patch_unauthenticated_start_succeeds(apps):
    """The vulnerability, reproduced: without the middleware an unauthenticated
    POST starts a scan. This is the control that proves Part B can see it."""
    pre, _ = apps
    assert status(pre, "POST", "/recon/victim/start") == 200


def test_post_patch_unauthenticated_start_rejected(apps):
    _, post = apps
    assert status(post, "POST", "/recon/victim/start") == 401


def test_post_patch_wrong_key_rejected(apps):
    _, post = apps
    assert status(post, "POST", "/recon/victim/start",
                  {"X-Orchestrator-Key": "wrong"}) == 401


def test_post_patch_correct_key_allowed(apps):
    _, post = apps
    assert status(post, "POST", "/recon/victim/start",
                  {"X-Orchestrator-Key": KEY}) == 200


def test_post_patch_health_exempt_without_key(apps):
    _, post = apps
    assert status(post, "GET", "/health") == 200


def test_post_patch_header_name_is_case_insensitive(apps):
    _, post = apps
    assert status(post, "POST", "/recon/victim/start",
                  {"x-orchestrator-key": KEY}) == 200
