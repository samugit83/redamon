---
name: Information Disclosure
description: Reference for finding info-disclosure leaks across DVCS / backups, debug endpoints, source maps, source bundles, headers, exports, observability, and CDN cache differentials.
---

# Information Disclosure

Reference for hunting and triaging information leaks. Pull this in when you need a comprehensive inventory of artifact paths to probe (`.git/`, `.env`, source maps, `__NEXT_DATA__`, observability endpoints) and a triage rubric to convert findings into actionable risk.

> Black-box scope: probes drive HTTP / WebSocket and observe response artifacts. Source-aware static analysis is out of scope; for that pivot to `/skill semgrep`.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Direct artifact probes | `execute_curl` | Capture full response bodies for evidence. |
| Mass artifact fuzz | `execute_ffuf` | Path / extension wordlists. |
| URL discovery from archives | `execute_gau` | Wayback + AlienVault + Common Crawl URLs. |
| Site crawl + JS extraction | `execute_katana` `-jc -jsl` | Then `kali_shell jsluice` per JS file. |
| Secrets scan on a cloned repo | `kali_shell betterleaks` / `semgrep p/secrets` | After `git clone`. |
| Diff harness across principals | `execute_curl` x N + `kali_shell diff/jq` | Same path, different tokens. |

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history first (proxy_brain only see traffic that crossed the capture proxy; blind artifact-path fuzzing for `/.git`, `/.env` and friends stays with `execute_ffuf`, since those were never requested).

- `redamon.grep` across all captured response bodies for secret patterns, tokens, API keys, and version strings (`AKIA`, `BEGIN PRIVATE KEY`, `password`, framework version markers).
- `redamon.query` / `redamon.search` to inventory disclosure headers already observed (`Server`, `X-Powered-By`, `Server-Timing`, `Via`, `X-Cache`, and the other cache headers).
- `redamon.sitemap` measures observed-endpoint coverage so the differential oracle runs against real captured paths.
- Differential oracle: `redamon.replay id mutate:{dropHeaders:["Authorization"], headers:{"Authorization":"Bearer $B"}}` re-requests one path as token A, token B, and anon, then `redamon.diff` the pair to expose cross-principal leakage (status / body length / ETag).

## Artifact path inventory

### DVCS

```
/.git/HEAD              /.git/config         /.git/index            /.git/logs/HEAD
/.git/refs/heads/main   /.git/objects/pack/  /.git/packed-refs       /.gitignore
/.svn/entries           /.svn/wc.db
/.hg/store              /.hg/dirstate
/.bzr/checkout/dirstate
/CVS/Entries
```

If `/.git/HEAD` returns a `ref: refs/heads/...` line, the directory is exposed; recover the repo:

```
kali_shell: git clone http://target.tld/.git /tmp/loot/repo || \
            (mkdir -p /tmp/loot/repo/.git && cd /tmp/loot/repo && \
             git init && \
             curl -s "http://target.tld/.git/HEAD" -o .git/HEAD && \
             # then walk pack files via git-dumper or similar
             true)
kali_shell: betterleaks git /tmp/loot/repo --git-workers 4 --exit-code 0 --report-path /tmp/loot/leaks.json --report-format json
```

### Config and secrets

```
/.env                   /.env.local            /.env.production       /.env.development
/.env.staging           /.env.dev              /.env.bak              /.env.example
/web.config             /appsettings.json      /appsettings.Development.json
/config.php             /config.json           /config.yaml           /config.yml
/settings.py            /local_settings.py     /database.yml          /credentials.json
/Dockerfile             /docker-compose.yml    /docker-compose.yaml   /docker-compose.override.yml
/.dockerignore          /.npmrc                /.yarnrc               /.pypirc
/serverless.yml         /netlify.toml          /vercel.json           /now.json
/firebase.json          /firebase-debug.log    /service-account.json
/credentials            /client_secret.json    /id_rsa                /id_dsa
/aws/credentials        /.aws/credentials      /.aws/config
/phpinfo.php            /info.php              /test.php              /__phpinfo.php
```

### Backup and editor swaps

```
/index.php~              /index.php.bak         /index.php.old         /index.php.swp
/index.php.swo           /index.php.tmp         /index.php.orig        /index.php#
/.DS_Store               /Thumbs.db
/backup.zip              /backup.tar.gz         /db.sql                /dump.sql
/<appname>.zip           /<appname>.tar         /site.zip              /export.json
```

`.DS_Store` parsing reveals all sibling filenames -> targeted probes.

### API schema and introspection

```
/openapi.json           /openapi.yaml          /api/openapi.json      /v1/openapi.json
/swagger.json           /swagger/v1/swagger.json
/api-docs               /api-docs.json         /docs                  /redoc
/graphql                # see /skill graphql for introspection probes
/grpc.reflection         # gRPC server reflection if reachable
/wsdl                    # SOAP
/wadl
```

### Client bundles and source maps

```
/static/js/main.<hash>.js
/static/js/main.<hash>.js.map
/_next/static/<buildId>/_buildManifest.js
/_next/static/<buildId>/_ssgManifest.js
/_next/static/chunks/main-*.js
/_next/static/chunks/main-*.js.map
/assets/index-<hash>.js          (Vite)
/assets/index-<hash>.js.map      (Vite source map)
/build/static/js/...              (Create React App)
```

`.map` files in production are an info-disclosure finding by themselves. Stack-mapped sources reveal action IDs, internal endpoints, prop shapes, library versions.

### Observability and admin

```
/metrics                /healthz               /status                /version
/api/health             /-/healthy              /-/ready               /readyz
/actuator               /actuator/env          /actuator/health       /actuator/configprops
/actuator/heapdump       /actuator/threaddump  /actuator/beans        /actuator/info
/debug/pprof/            /debug/pprof/heap     /debug/pprof/profile
/_profiler               /_debug                /_dashboard
/grafana                 /kibana                /prometheus            /jaeger
/swagger-ui              /h2-console            /elmah.axd             /trace.axd
```

`actuator/heapdump` is critical: full JVM heap, including secrets in memory. `pprof/heap` similar for Go.

### Hosting / cloud platform

```
/.well-known/security.txt           /.well-known/openid-configuration
/.well-known/oauth-authorization-server
/sitemap.xml                        /sitemap_index.xml
/robots.txt                         /humans.txt
/crossdomain.xml                    /clientaccesspolicy.xml
```

### Headers worth grepping

```
Server:                  X-Powered-By:          X-AspNet-Version:    X-AspNetMvc-Version:
X-Generator:             X-Drupal-Cache:        X-Pingback:           X-Runtime:
X-Backend-Server:        Via:                    X-Cache:              X-Cache-Hits:
X-Request-Id:            X-Trace-Id:             traceparent:           Server-Timing:
```

`Server-Timing` often reveals internal hostnames and feature names. `Via:` reveals proxy chain.

## Differential oracle harness

Compare a single resource across principals:

```
execute_curl url: "https://target.tld/api/orders/X" headers: "Authorization: Bearer $A"
execute_curl url: "https://target.tld/api/orders/X" headers: "Authorization: Bearer $B"
execute_curl url: "https://target.tld/api/orders/X"   # anon
```

Track:

| Channel | Signal |
|---|---|
| Status code | `404` vs `403` vs `200` reveals existence |
| Body length | Same body with different lengths reveals minor variants |
| ETag / Last-Modified | Identical headers across users -> shared cache |
| `Cache-Control` | `public` on user-bound responses |
| `Set-Cookie` | New cookies show server-side state |
| Response time | Constant-time vs variable-time reveals branch |

HEAD vs GET: `HEAD /api/orders/X` returns headers only and is often unprotected.

Conditional requests:

```
execute_curl url: "https://target.tld/api/orders/X" headers: "If-None-Match: \"someETag\""
# 304 = exists; 200 = different ETag; 404 = absent
```

## Cache and CDN poisoning oracles

| Probe | Symptom |
|---|---|
| Identical responses for two different users | Cache key missing user identity |
| Anon request after authed populates the cache | Cross-user cache poisoning |
| `Vary` lists `Accept-Encoding` only | Should include `Authorization` / `Cookie` |
| Stale `200` after the underlying resource changed | TTL-driven info disclosure |
| `206 Partial Content` on a cached object | Partial fragments leak |

```
execute_curl url: "https://target.tld/api/me" headers: "Authorization: Bearer $A"
execute_curl url: "https://target.tld/api/me"
# If both return User A's data, the CDN keys without auth.
```

## Cross-channel mirroring

| Channel A | Channel B | Probe |
|---|---|---|
| REST | GraphQL | Same logical query; one path may leak fields the other strips |
| SSR HTML | JSON API | SSR strips fields; JSON returns full record |
| HTTP | WebSocket | Same operation different per-message auth |
| API | gRPC | Reflection enabled, CORS open, method names leak |

## Triage rubric

- **Critical**: credentials, signed-URL signatures, `service_role` / admin tokens, full config dumps, JVM/Go heap dumps, AD machine-account hashes, signing-key material.
- **High**: precise component versions with reachable CVEs, cross-tenant data via cache, source maps revealing hidden admin endpoints, `.git/` reachable, betterleaks-positive `.env`.
- **Medium**: internal hostnames / IP ranges enabling LFI / SSRF pivots, debug pages on staging surfaces, OpenAPI exposing privileged operations.
- **Low**: generic banners, marketing version strings, intentional public docs, owner-only metadata that doesn't cross identity / tenant boundaries.

## Exploitation chains

### .env -> cloud takeover

```
1. /.env returns AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY
2. kali_shell: aws sts get-caller-identity --profile leaked
3. Enumerate IAM perms; if SES / S3 / Lambda perms present, escalate
```

(AWS CLI may not be present in the Kali image; use `execute_code` with `boto3` or fall back to the AWS REST API via `execute_curl` + SigV4.)

### Source maps -> hidden admin endpoints

```
1. Find /static/js/main-<hash>.js.map
2. Parse via execute_code (sourcemap python lib) -> reveals admin route paths and function names
3. Probe each admin route with anon / user / admin tokens
```

### Stack trace -> path traversal

```
1. Trigger an exception revealing /home/app/services/api/v1/handlers/users.py:42
2. Probe / with traversal to read /home/app/.env
3. Chain to the .env -> creds path
```

### Schema -> forgotten authz

```
1. /openapi.json reveals /api/internal/admin-only operations not visible in UI
2. Send anon and user tokens to each
3. Anything returning 200 instead of 401/403 is a finding
```

## Validation shape

A clean info-disclosure finding includes:

1. The exact request URL.
2. The leaked artifact (raw body, header, or relevant fragment redacted to a fingerprint when sensitive).
3. Triage class explained (Critical / High / Medium / Low) with the chain to impact.
4. A minimal request set: not "I dumped the entire repo," but "this single GET to `/.git/config` returned a remote URL and credentials."

## False positives

- Public marketing version banners with no exploitable surface.
- Intentional `/.well-known/security.txt` and `humans.txt` content.
- Owner-visible-only data on `/me`-style endpoints; no cross-identity boundary crossed.
- Generic `404` body that hints at a framework but does not reveal version or stack trace.

## Hand-off

```
.git / repo dump          -> kali_shell betterleaks (then /skill semgrep on the cloned tree)
source maps recovered     -> probe each new endpoint with the standard auth matrix
debug / actuator dumps    -> immediately notify operator if heap / env exposure
cache leaks               -> file as Cross-User Cache Poisoning
schema -> hidden admin    -> built-in / community skills per the implicated vuln class
```
