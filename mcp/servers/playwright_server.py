"""
Playwright MCP Server - Browser Automation

Exposes Playwright browser automation as an MCP tool for agentic penetration testing.
Enables JS-rendered content extraction and interactive browser scripting.

Tools:
    - execute_playwright: Extract rendered page content or run Playwright scripts
"""

from fastmcp import FastMCP
import subprocess
import tempfile
import textwrap
import re
import os

# Chromium launch constants live in browser_launch so this server and the
# in-process `redamon` SDK cannot drift on the root/Docker flags.
from browser_launch import BROWSER_ARGS, CHROME_UA

# Strip ANSI escape codes (terminal colors) from output
ANSI_ESCAPE = re.compile(r'\x1b\[[0-9;]*[a-zA-Z]')

# Server configuration
SERVER_NAME = "playwright"
SERVER_HOST = os.getenv("MCP_HOST", "0.0.0.0")
SERVER_PORT = int(os.getenv("PLAYWRIGHT_PORT", "8005"))

mcp = FastMCP(SERVER_NAME)


def _run_playwright_script(script: str, timeout: int = 45) -> str:
    """Run a Playwright Python script in a subprocess and return its stdout."""
    script_path = None
    try:
        with tempfile.NamedTemporaryFile(
            mode='w', suffix='.py', delete=False, dir='/tmp'
        ) as f:
            f.write(script)
            f.flush()
            script_path = f.name

        result = subprocess.run(
            ['python3', script_path],
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = ANSI_ESCAPE.sub('', result.stdout)
        if result.returncode != 0 and result.stderr:
            clean_stderr = ANSI_ESCAPE.sub('', result.stderr)
            # Filter out playwright verbose logging
            stderr_lines = [
                line for line in clean_stderr.split('\n')
                if line.strip() and not line.strip().startswith('[')
            ]
            if stderr_lines:
                output += f"\n[STDERR]: {chr(10).join(stderr_lines)}"

        return output if output.strip() else "[INFO] Script completed with no output"

    except subprocess.TimeoutExpired:
        return f"[ERROR] Script timed out after {timeout} seconds."
    except Exception as e:
        return f"[ERROR] {str(e)}"
    finally:
        if script_path:
            try:
                os.unlink(script_path)
            except OSError:
                pass


@mcp.tool()
def execute_playwright(url: str = "", script: str = "", selector: str = "", format: str = "text", _redamon_ctx: str = "") -> str:
    """
    Browser automation tool with two modes: content extraction or custom scripting.

    **Mode 1 — Content extraction** (provide `url`, optionally `selector` and `format`):
    Navigate to a URL with a real browser and extract the rendered content.
    Unlike curl, this fully renders JavaScript — perfect for SPAs and dynamic pages.

    **Mode 2 — Custom script** (provide `script`):
    Run a Playwright Python script for complex multi-step interactions.
    Variables `browser`, `context`, and `page` are pre-initialized.
    Use print() for output.

    Args:
        url: URL to navigate to (Mode 1). Ignored if script is provided.
        script: Python code using Playwright sync API (Mode 2). If provided, url/selector/format are ignored.
        selector: CSS selector to extract specific element (Mode 1, default: entire page body)
        format: "text" for visible text, "html" for inner HTML (Mode 1, default: "text")

    Returns:
        Mode 1: Extracted page content (text or HTML)
        Mode 2: Script stdout (whatever you print())

    Examples:
        Get all visible text from a page:
        - url="http://10.0.0.5:3000"

        Get HTML of a login form:
        - url="http://10.0.0.5/login" selector="form" format="html"

        Login and capture authenticated page:
        - script="page.goto('http://10.0.0.5/login')\\npage.fill('#username', 'admin')\\npage.fill('#password', 'pass')\\npage.click('button[type=submit]')\\npage.wait_for_load_state('networkidle')\\nprint(page.inner_text('body')[:3000])"

        Test XSS in search field:
        - script="page.goto('http://10.0.0.5/search')\\npage.fill('input[name=q]', '<script>alert(1)</script>')\\npage.click('button[type=submit]')\\npage.wait_for_load_state('networkidle')\\nprint(page.content()[:5000])"
    """
    if script.strip():
        return _execute_script_mode(script, _redamon_ctx)
    elif url.strip():
        return _execute_content_mode(url, selector, format, _redamon_ctx)
    else:
        return "[ERROR] Provide either 'url' (content extraction) or 'script' (custom automation)."


def _capture_playwright_args(ctx_token: str):
    """Return (proxy_kwarg, header_kwarg) f-string fragments for the browser
    launch/context when routing through the capture proxy, else ('', ''). §20.2:
    both are added together, only when reachable."""
    try:
        from capture_routing import agent_capture_routing
        cap_url, cap_tok = agent_capture_routing(ctx_token)
    except Exception:
        cap_url, cap_tok = (None, None)
    if not (cap_url and cap_tok):
        return ("", "")
    # ignore_https_errors is REQUIRED when routing: the capture proxy MITMs TLS with
    # its own CA, which the browser does not trust, so without this every https
    # navigation fails with ERR_CERT_AUTHORITY_INVALID and nothing is captured.
    # Only emitted when capture is on, so non-capture playwright keeps strict TLS.
    return (
        f'proxy={{"server": {cap_url!r}}},',
        f'extra_http_headers={{"X-Redamon-Ctx": {cap_tok!r}}}, ignore_https_errors=True,',
    )


def _capture_launch_patch(ctx_token: str) -> str:
    """Monkeypatch fragment for SELF-CONTAINED scripts (they bring their own
    `sync_playwright()`, so the wrapper's proxy=/extra_http_headers kwargs never
    apply). Forces every browser launch through the capture proxy and stamps the
    X-Redamon-Ctx header on every context (new_context also backs Browser.new_page
    in playwright-python) and persistent context. Empty when not routing (§20.2:
    proxy + header added together, only when reachable)."""
    try:
        from capture_routing import agent_capture_routing
        cap_url, cap_tok = agent_capture_routing(ctx_token)
    except Exception:
        cap_url, cap_tok = (None, None)
    if not (cap_url and cap_tok):
        return ""
    return textwrap.dedent(f"""\
        import playwright.sync_api as _pw_cap
        _pw_cap_url = {cap_url!r}
        _pw_cap_hdr = {{"X-Redamon-Ctx": {cap_tok!r}}}
        _pw_cap_L = _pw_cap.BrowserType.launch
        def _pw_cap_launch(self, **kw):
            kw["proxy"] = {{"server": _pw_cap_url}}
            return _pw_cap_L(self, **kw)
        _pw_cap.BrowserType.launch = _pw_cap_launch
        _pw_cap_C = _pw_cap.Browser.new_context
        def _pw_cap_new_context(self, **kw):
            _h = dict(kw.get("extra_http_headers") or {{}}); _h.update(_pw_cap_hdr)
            kw["extra_http_headers"] = _h
            kw["ignore_https_errors"] = True  # trust the capture proxy's MITM CA
            return _pw_cap_C(self, **kw)
        _pw_cap.Browser.new_context = _pw_cap_new_context
        _pw_cap_P = _pw_cap.BrowserType.launch_persistent_context
        def _pw_cap_persistent(self, *a, **kw):
            kw["proxy"] = {{"server": _pw_cap_url}}
            _h = dict(kw.get("extra_http_headers") or {{}}); _h.update(_pw_cap_hdr)
            kw["extra_http_headers"] = _h
            kw["ignore_https_errors"] = True  # trust the capture proxy's MITM CA
            return _pw_cap_P(self, *a, **kw)
        _pw_cap.BrowserType.launch_persistent_context = _pw_cap_persistent
    """)


def _execute_content_mode(url: str, selector: str, format: str, ctx_token: str = "") -> str:
    """Mode 1: Navigate to URL and extract rendered content."""
    use_html = format.lower() == "html"
    max_chars = 40000
    _proxy_kw, _hdr_kw = _capture_playwright_args(ctx_token)

    script = textwrap.dedent(f"""\
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                {_proxy_kw}
                args={BROWSER_ARGS!r}
            )
            context = browser.new_context(
                user_agent={CHROME_UA!r},
                {_hdr_kw}
            )
            page = context.new_page()

            try:
                page.goto({url!r}, wait_until="networkidle", timeout=30000)
            except Exception as e:
                print(f"[ERROR] Navigation failed: {{e}}")
                context.close()
                browser.close()
                raise SystemExit(1)

            try:
                selector = {selector!r}
                use_html = {use_html!r}
                max_chars = {max_chars!r}

                if selector:
                    element = page.query_selector(selector)
                    if not element:
                        print(f"[INFO] No element found matching selector: {{selector}}")
                        raise SystemExit(0)
                    if use_html:
                        content = element.inner_html()
                    else:
                        content = element.inner_text()
                else:
                    if use_html:
                        content = page.content()
                    else:
                        content = page.inner_text("body")

                if len(content) > max_chars:
                    content = content[:max_chars] + "\\n\\n[TRUNCATED - content exceeded " + str(max_chars) + " chars]"

                if content.strip():
                    print(content)
                else:
                    print("[INFO] Page rendered but no content extracted")
            finally:
                context.close()
                browser.close()
    """)

    return _run_playwright_script(script, timeout=45)


_FORBIDDEN_ASYNC_PATTERNS = [
    (re.compile(r'(?<![A-Za-z0-9_])await\s'), 'await'),
    (re.compile(r'(?<![A-Za-z0-9_])asyncio\.run\b'), 'asyncio.run()'),
    (re.compile(r'(?<![A-Za-z0-9_])async\s+def\b'), 'async def'),
    (re.compile(r'(?m)^\s*import\s+asyncio\b'), 'import asyncio'),
    (re.compile(r'(?<![A-Za-z0-9_])async_playwright\b'), 'async_playwright'),
]


# A script that opens its own `sync_playwright()` context is "self-contained":
# it manages the full browser lifecycle itself. Wrapping such a script inside the
# tool's own `with sync_playwright() as p:` block nests two sync contexts, and the
# inner __enter__ aborts with the misleading "Sync API inside the asyncio loop"
# error (the outer context's event loop is already running). Detect this case and
# run the script raw instead of wrapping it.
_SELF_CONTAINED_RE = re.compile(r'(?<![A-Za-z0-9_])sync_playwright\s*\(')

# Preamble for self-contained scripts: force the Docker/root browser args onto every
# launch() call so the agent does not have to remember --no-sandbox (chromium crashes
# as root without it). Patches BrowserType.launch so it works for chromium/firefox/webkit.
_LAUNCH_PATCH = textwrap.dedent(f"""\
    import playwright.sync_api as _pw_sync
    _pw_orig_launch = _pw_sync.BrowserType.launch
    def _pw_patched_launch(self, **kw):
        _args = list(kw.get("args") or [])
        for _a in {BROWSER_ARGS!r}:
            if _a not in _args:
                _args.append(_a)
        kw["args"] = _args
        kw.setdefault("headless", True)
        return _pw_orig_launch(self, **kw)
    _pw_sync.BrowserType.launch = _pw_patched_launch
""")


def _execute_script_mode(user_script: str, ctx_token: str = "") -> str:
    """Mode 2: Run arbitrary Playwright Python script with pre-initialized browser."""
    _proxy_kw, _hdr_kw = _capture_playwright_args(ctx_token)
    for pattern, name in _FORBIDDEN_ASYNC_PATTERNS:
        if pattern.search(user_script):
            return (
                f"[ERROR] execute_playwright uses Playwright SYNC API. "
                f"Found '{name}' in your script -- remove it. "
                f"Replace 'await page.X(...)' with 'page.X(...)'. "
                f"Replace 'asyncio.sleep(s)' with 'page.wait_for_timeout(s*1000)'. "
                f"Do NOT wrap your code in 'async def' or 'asyncio.run()' -- "
                f"the wrapper already runs inside `with sync_playwright() as p:`."
            )

    # Self-contained script (brings its own `sync_playwright()` context): run it raw
    # so we don't nest two sync contexts. Inject browser args via a launch monkeypatch,
    # and (when capture is on) force the proxy + X-Redamon-Ctx via _capture_launch_patch
    # so self-contained scripts are captured like the wrapped path.
    if _SELF_CONTAINED_RE.search(user_script):
        return _run_playwright_script(
            _LAUNCH_PATCH + _capture_launch_patch(ctx_token) + user_script, timeout=60)

    # Build wrapper script with correct indentation
    lines = [
        "from playwright.sync_api import sync_playwright",
        "",
        "with sync_playwright() as p:",
        f"    browser = p.chromium.launch(headless=True, {_proxy_kw} args={BROWSER_ARGS!r})",
        f"    context = browser.new_context(user_agent={CHROME_UA!r}, {_hdr_kw} viewport={{\"width\": 1280, \"height\": 720}})",
        "    page = context.new_page()",
        "    try:",
    ]
    # User script at 8-space indent (inside try: which is inside with:)
    has_code = False
    for line in user_script.splitlines():
        if line.strip():
            lines.append("        " + line)
            has_code = True
        else:
            lines.append("")
    if not has_code:
        lines.append("        pass")
    lines.extend([
        "    finally:",
        "        context.close()",
        "        browser.close()",
    ])
    wrapper = "\n".join(lines) + "\n"

    return _run_playwright_script(wrapper, timeout=60)


if __name__ == "__main__":
    # Check transport mode from environment
    transport = os.getenv("MCP_TRANSPORT", "stdio")

    if transport == "sse":
        mcp.run(transport="sse", host=SERVER_HOST, port=SERVER_PORT)
    else:
        mcp.run(transport="stdio")
