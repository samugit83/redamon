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


# Common Playwright launch args for Docker/root environment
BROWSER_ARGS = [
    '--no-sandbox',
    '--disable-setuid-sandbox',
    '--disable-dev-shm-usage',
    '--disable-gpu',
]

CHROME_UA = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)


@mcp.tool()
def execute_playwright(url: str = "", script: str = "", selector: str = "", format: str = "text") -> str:
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
        return _execute_script_mode(script)
    elif url.strip():
        return _execute_content_mode(url, selector, format)
    else:
        return "[ERROR] Provide either 'url' (content extraction) or 'script' (custom automation)."


def _execute_content_mode(url: str, selector: str, format: str) -> str:
    """Mode 1: Navigate to URL and extract rendered content."""
    use_html = format.lower() == "html"
    max_chars = 40000

    script = textwrap.dedent(f"""\
        from playwright.sync_api import sync_playwright

        with sync_playwright() as p:
            browser = p.chromium.launch(
                headless=True,
                args={BROWSER_ARGS!r}
            )
            context = browser.new_context(
                user_agent={CHROME_UA!r},
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


def _execute_script_mode(user_script: str) -> str:
    """Mode 2: Run arbitrary Playwright Python script with pre-initialized browser."""
    # Build wrapper script with correct indentation
    lines = [
        "from playwright.sync_api import sync_playwright",
        "",
        "with sync_playwright() as p:",
        f"    browser = p.chromium.launch(headless=True, args={BROWSER_ARGS!r})",
        f"    context = browser.new_context(user_agent={CHROME_UA!r}, viewport={{\"width\": 1280, \"height\": 720}})",
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
