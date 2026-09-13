"""
Validates the Authenticated Session Recording feature against the auth_target
guinea pig, using RedAmon's OWN builder rather than a reimplementation.

Run inside the recon image, joined to pentest-net:

  docker run --rm --network redamon_pentest-net \
    -v "$PWD":/repo -w /repo -e PYTHONPATH=/repo/recon:/repo:/repo/scanners/capture_proxy \
    --entrypoint python redamon-recon:latest \
    testing/guinea_pigs/auth_target/validate_auth_recording.py

What it proves, in order:
  1. A real login against the target issues a real session cookie.
  2. recon's merge_auth_headers attaches that session for in-scope hosts,
     including DISCOVERED subdomains (the apex-only bug), and refuses a
     foreign host.
  3. An AUTHENTICATED crawl reaches post-login pages an ANONYMOUS crawl cannot.
     This is the feature's whole purpose and the one claim unit tests cannot make.
  4. Every auth TYPE reaches the target correctly (bearer/basic/apikey/header).
  5. The target-controlled hostile cookie (';;') is refused by the builder, and
     an oversized cookie is dropped rather than truncated by the extractor.
"""
import re
import sys
from collections import deque
from urllib.parse import urljoin, urlparse

import requests

from recon.helpers.auth_profile import merge_auth_headers, build_auth_headers
from session_extract import extract_session

APEX = "authpig.test"
BASE = "http://app.authpig.test:5000"
API_HOST = "http://api.authpig.test:5000"
FOREIGN = "outsider.example-evil.test"
CSRF_TOKEN = "csrf-authpig-789"

failures: list[str] = []
passes: list[str] = []


def check(name: str, ok: bool, detail: str = "") -> None:
    (passes if ok else failures).append(name)
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}{(' — ' + detail) if detail else ''}")


def headers_to_dict(lines):
    out = {}
    for line in lines:
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def crawl(start: str, headers: dict, max_pages: int = 40) -> dict:
    """Tiny BFS crawler: what a link-following crawler would reach with these
    headers. Returns {url: markers found}."""
    seen, found = set(), {}
    q = deque([start])
    while q and len(seen) < max_pages:
        url = q.popleft()
        if url in seen:
            continue
        seen.add(url)
        try:
            r = requests.get(url, headers=headers, timeout=10, allow_redirects=False)
        except Exception:
            continue
        body = r.text or ""
        markers = re.findall(r"(AUTHONLY-[A-Z0-9-]+|PUBLIC-[A-Z-]+)", body)
        if markers:
            found[url] = sorted(set(markers))
        for href in re.findall(r'href="([^"]+)"', body):
            nxt = urljoin(url, href)
            if urlparse(nxt).hostname == urlparse(start).hostname and nxt not in seen:
                q.append(nxt)
    return found


def main() -> int:
    print("\n=== 1. real login against the target ===")
    s = requests.Session()
    r = s.post(f"{BASE}/login",
               data={"username": "operator", "password": "hunter2", "csrf_token": CSRF_TOKEN},
               allow_redirects=False, timeout=10)
    cookie_name = "authpig_session"
    session_value = s.cookies.get(cookie_name)
    check("login issues a Set-Cookie session", bool(session_value), f"{cookie_name}={session_value}")
    if not session_value:
        return 1
    cookie_header = f"{cookie_name}={session_value}"

    settings = {
        "TARGET_DOMAIN": APEX,
        "SUBDOMAIN_LIST": [],           # full discovery: the realistic default
        "AUTH_PROFILE": {"authType": "cookie", "authValue": cookie_header, "extraHeaders": {}},
    }

    print("\n=== 2. recon builder attaches the session for in-scope hosts ===")
    disc = merge_auth_headers([], settings, ["app.authpig.test", "api.authpig.test", APEX])
    check("discovered subdomains get the session", disc == [f"Cookie: {cookie_header}"], str(disc))
    foreign = merge_auth_headers([], settings, ["app.authpig.test", FOREIGN])
    check("a foreign host suppresses the session entirely", foreign == [], str(foreign))

    print("\n=== 3. authenticated crawl reaches the post-login surface ===")
    auth_headers = headers_to_dict(disc)
    anon_found = crawl(BASE, {})
    auth_found = crawl(BASE, auth_headers)

    anon_markers = {m for ms in anon_found.values() for m in ms}
    auth_markers = {m for ms in auth_found.values() for m in ms}
    gained = sorted(auth_markers - anon_markers)

    check("anonymous crawl sees only public pages",
          all(m.startswith("PUBLIC-") for m in anon_markers), str(sorted(anon_markers)))
    check("authenticated crawl reaches AUTHONLY pages",
          any(m.startswith("AUTHONLY-") for m in auth_markers), str(sorted(auth_markers)))
    check("authenticated crawl STRICTLY gains post-login surface", len(gained) >= 5, str(gained))
    print(f"     anonymous URLs: {len(anon_found)}   authenticated URLs: {len(auth_found)}")

    print("\n=== 4. every auth type reaches the target ===")
    tok = requests.post(f"{BASE}/auth/token", json={"username": "operator"}, timeout=10).json()["token"]
    modes = [
        ("bearer", {"authType": "bearer", "authValue": tok}, "/auth/bearer"),
        ("basic", {"authType": "basic", "authValue": "operator:hunter2"}, "/auth/basic"),
        ("apikey", {"authType": "apikey", "authValue": "apikey-authpig-123",
                    "authHeaderName": "X-API-Key"}, "/auth/apikey"),
        ("header", {"authType": "header", "authValue": "xauth-authpig-456",
                    "authHeaderName": "X-Auth-Token"}, "/auth/header"),
        ("cookie", {"authType": "cookie", "authValue": cookie_header}, "/api/v1/me"),
    ]
    for label, profile, path in modes:
        hdrs = build_auth_headers(profile, log_prefix=None)
        resp = requests.get(f"{BASE}{path}", headers=hdrs, timeout=10)
        check(f"{label} mode authenticates ({path})", resp.status_code == 200,
              f"HTTP {resp.status_code}")

    print("\n=== 5. hostile / oversized material is refused ===")
    evil = requests.get(f"{BASE}/edge/evil-cookie", timeout=10)
    evil_val = evil.headers.get("Set-Cookie", "")
    hostile = {"authType": "cookie", "authValue": evil_val.split(";")[0] + ";;X-Redamon-Ctx: forged"}
    check("cookie carrying ';;' is refused by the builder",
          build_auth_headers(hostile, log_prefix=None) == {})

    huge = requests.get(f"{BASE}/edge/huge-cookie", timeout=10)
    rec = {"host": "app.authpig.test",
           "reqHeaders": {}, "respHeaders": {"Set-Cookie": huge.headers.get("Set-Cookie", "")}}
    check("oversized cookie is DROPPED, not truncated", "cookie" not in extract_session(rec))

    multi = requests.get(f"{BASE}/edge/multi-cookie", timeout=10)
    raw = multi.raw.headers.getlist("Set-Cookie") if hasattr(multi.raw, "headers") else []
    rec2 = {"host": "app.authpig.test", "reqHeaders": {}, "respHeaders": {"Set-Cookie": raw}}
    got = extract_session(rec2).get("cookie", "")
    check("multiple Set-Cookie headers are merged", "first=one" in got and "second=two" in got, got)

    print("\n=== 6. the internal capture tag never reaches the target ===")
    who = requests.get(f"{BASE}/whoami", headers=auth_headers, timeout=10).json()
    check("target received the session cookie", who.get("cookie") == cookie_header)
    check("target never saw X-Redamon-Ctx", who.get("x_redamon_ctx") is None)

    print(f"\n{'=' * 60}\nRESULT: {len(passes)} passed, {len(failures)} failed")
    if failures:
        for f in failures:
            print(f"  FAILED: {f}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
