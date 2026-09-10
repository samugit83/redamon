---
name: OpenAPI Swagger Exposure
description: Reference for finding OpenAPI / Swagger spec leaks covering common discovery paths, schema-to-endpoint mapping, hidden / deprecated / debug operations, environment-leak patterns, and parameter-shape mining.
---

# OpenAPI / Swagger Exposure

Reference for finding API specs leaked in production and converting them into a probe inventory. Pull this in when the target serves `/openapi.json`, `/swagger.json`, `/docs`, or `/api-docs`. A leaked spec is a treasure map: every endpoint, every parameter, every auth scheme, every example value.

> Black-box scope: probes drive HTTP, fetch JSON / YAML specs, and parse them with `jq` / Python. Operations that are documented but undocumented in the UI are common leaks.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Fetch the spec | `execute_curl` | Try multiple paths; some apps serve only YAML. |
| Parse + extract | `kali_shell jq` | One-line extraction patterns below. |
| Fuzz hidden routes derived from prefixes | `execute_ffuf` | Build a wordlist from spec paths + admin / debug names. |
| Parameter discovery on each route | `execute_arjun` | Find params not in the spec. |
| Scan with the spec as input | `execute_nuclei -im openapi -l <spec>` | Nuclei consumes OpenAPI / Swagger directly. |

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, redamon.grep over captured response bodies can catch a spec leaked inline (`{"openapi":` or `{"swagger":`) that a fixed path sweep misses, and redamon.get reads it. redamon.sitemap (endpoints actually observed in traffic) diffed against the spec's declared paths is a direct spec-drift and hidden-operation detector, and redamon.params compares declared parameters against the ones the handler actually accepts. redamon.replay probes operations marked `security: []` for real unauth access. Where the proxy stops: the core workflow stays fetch-and-parse plus execute_ffuf / execute_arjun / execute_nuclei against the parsed spec.

## Discovery paths

The OpenAPI 3.0 / Swagger 2.0 spec lives at `/openapi.json` or `/swagger.json` by convention, but apps publish under many aliases:

```
/openapi.json                       /openapi.yaml
/swagger.json                       /swagger.yaml
/api-docs                           /api-docs.json
/api/openapi.json                   /api/swagger.json
/v1/openapi.json                    /v2/openapi.json
/v1/swagger.json                    /v2/api-docs
/docs                               /docs.json
/redoc                              /redoc.json
/swagger                             /swagger-ui.html
/swagger-resources                  /swagger-resources/configuration/security
/swagger-config.json
/openapi.yaml.backup                 /api-docs.bak
/internal/openapi.json               /staging/openapi.json   /dev/openapi.json
/.well-known/openapi.json
```

WSDL-style aliases on REST APIs:

```
/api/?format=openapi                 /api/?format=swagger
/api?wsdl                             (sometimes returns OpenAPI YAML on hybrid services)
```

Framework defaults:

| Framework | Default |
|---|---|
| FastAPI | `/openapi.json`, `/docs`, `/redoc` |
| NestJS (`@nestjs/swagger`) | `/api`, `/api-json`, `/api-docs`, `/swagger` |
| Spring Boot | `/v3/api-docs`, `/swagger-ui.html`, `/v2/api-docs` (legacy) |
| ASP.NET (Swashbuckle) | `/swagger/v1/swagger.json`, `/swagger` |
| Django REST + drf-yasg | `/swagger.json`, `/swagger.yaml`, `/redoc/` |
| Flask + flasgger | `/apispec.json`, `/apidocs/` |
| Hapi (hapi-swagger) | `/documentation`, `/swagger.json` |
| Strapi | `/documentation/v1.0.0` |

## Probe matrix

### Discovery sweep

```
execute_code language: python
import requests
PATHS = [
    "/openapi.json", "/swagger.json", "/api-docs", "/api-docs.json",
    "/api/openapi.json", "/api/swagger.json", "/v1/openapi.json", "/v2/api-docs",
    "/swagger/v1/swagger.json", "/v3/api-docs", "/v1/swagger.json",
    "/docs", "/redoc", "/swagger", "/swagger-ui.html", "/swagger-resources",
    "/internal/openapi.json", "/staging/openapi.json", "/dev/openapi.json",
    "/.well-known/openapi.json", "/api?wsdl", "/openapi.yaml", "/swagger.yaml",
]
for p in PATHS:
    r = requests.get(f"https://target.tld{p}", timeout=10, allow_redirects=False)
    print(f"{r.status_code}\t{len(r.content):>8}\t{p}")
```

200 + `application/json` body containing `{"openapi":` or `{"swagger":` is a hit.

### Spec parsing

```
kali_shell: curl -s https://target.tld/openapi.json -o /tmp/spec.json

# All paths
kali_shell: jq -r '.paths | keys[]' /tmp/spec.json | sort -u | wc -l

# Per-path methods
kali_shell: jq -r '.paths | to_entries[] | "\(.key)\t\(.value | keys | join(","))"' /tmp/spec.json | sort

# Auth schemes
kali_shell: jq '.components.securitySchemes' /tmp/spec.json
kali_shell: jq '.securityDefinitions' /tmp/spec.json   # Swagger 2.0

# Servers (often hint at hidden envs)
kali_shell: jq '.servers' /tmp/spec.json
kali_shell: jq '.host, .basePath, .schemes' /tmp/spec.json   # Swagger 2.0

# Operations marked deprecated (low-priority gating)
kali_shell: jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | select(.value.deprecated==true) | "\($p)\t\(.key)"' /tmp/spec.json

# Operations with sensitive tags
kali_shell: jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | select(.value.tags // [] | any(test("admin|internal|debug|test";"i"))) | "\($p)\t\(.key)\t\(.value.tags)"' /tmp/spec.json

# Operations that take a file upload
kali_shell: jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | select((.value.requestBody.content // {}) | keys | any(test("multipart"))) | "\($p)\t\(.key)"' /tmp/spec.json

# Required vs optional parameters per operation (sample one path)
kali_shell: jq '.paths."/users"."get".parameters' /tmp/spec.json
```

### Server URL leaks

`servers` array often reveals hidden environments:

```json
"servers": [
  {"url": "https://api.target.tld/v1"},
  {"url": "https://staging-api.target.tld/v1"},
  {"url": "https://dev.internal.target.tld/v1"},
  {"url": "http://localhost:3000/v1"}
]
```

Probe each server URL with the same spec; staging often has weaker auth + more permissive CORS.

### Hidden operation discovery

OpenAPI's `include_in_schema=False` (FastAPI), `[ApiExplorerSettings(IgnoreApi = true)]` (.NET), and Swagger `x-internal: true` extensions hide operations. They are still callable.

Build a wordlist from spec prefixes + admin / debug suffixes:

```
kali_shell: jq -r '.paths | keys[]' /tmp/spec.json | grep -oE '^/[^/]+' | sort -u > /tmp/prefixes.txt

# Common hidden suffixes to fuzz
cat > /tmp/hidden.txt <<EOF
admin
internal
debug
test
health
metrics
status
config
flags
admin/users
admin/jobs
internal/health
debug/info
v0
v1-internal
EOF

# Fuzz each prefix with hidden suffixes
while read p; do
  execute_ffuf args: "-w /tmp/hidden.txt -u https://target.tld${p}/FUZZ -mc 200,401,403,422 -ac -t 20 -rate 50 -noninteractive -of json -o /tmp/ffuf_${p//\//_}.json"
done < /tmp/prefixes.txt
```

### Parameter shape mining

Spec lists declared parameters; the actual handler often accepts more. Run `execute_arjun` per route:

```
kali_shell: jq -r '.paths | keys[]' /tmp/spec.json > /tmp/spec_paths.txt
sed -i 's,^,https://target.tld,' /tmp/spec_paths.txt
execute_arjun args: "-i /tmp/spec_paths.txt -m GET -oJ /tmp/arjun_get.json"
execute_arjun args: "-i /tmp/spec_paths.txt -m POST -oJ /tmp/arjun_post.json"
```

### Auth scheme inventory

```
kali_shell: jq '.components.securitySchemes' /tmp/spec.json

# Example output:
# {
#   "BearerAuth": {"type":"http","scheme":"bearer","bearerFormat":"JWT"},
#   "ApiKeyAuth": {"type":"apiKey","in":"header","name":"X-API-Key"},
#   "OAuth2":     {"type":"oauth2","flows":{...}}
# }
```

Per-operation `security` blocks reveal which scheme each operation requires:

```
kali_shell: jq -r '.paths | to_entries[] | .key as $p | .value | to_entries[] | "\($p)\t\(.key)\t\((.value.security // []) | tostring)"' /tmp/spec.json
```

Operations with `security: []` (empty array) are explicitly UNAUTHENTICATED. Probe each.

### Spec drift / parity

Multiple specs on the same target often disagree:

```
kali_shell: diff <(curl -s https://target.tld/openapi.json | jq '.paths | keys') <(curl -s https://target.tld/v2/openapi.json | jq '.paths | keys')
```

Operations in v1 sometimes survive without the v2 hardening.

### Stage / dev environment leak

Some teams host dev / staging Swagger from the production hostname:

```
GET /staging-openapi.json
GET /dev-openapi.json
GET /openapi.json?env=internal
GET /openapi.json/.bak
```

These specs typically reveal far more endpoints than the production spec.

### Embedded Swagger UI

When `/docs` is served:

- Some Swagger UIs auto-load `https://petstore.swagger.io/v2/swagger.json` if no spec URL is configured -> harmless but indicates default config.
- Some allow loading arbitrary spec URLs via query param: `/swagger?spec=https://attacker.tld/spec.json`. If the page renders, attacker can craft a malicious spec that triggers stored-XSS in the Swagger UI viewer.

## Nuclei scan from OpenAPI

```
kali_shell: curl -s https://target.tld/openapi.json -o /tmp/spec.json
execute_nuclei args: "-l /tmp/spec.json -im openapi -as -j -o /tmp/nuclei_api.jsonl"
```

Nuclei templates with `http-openapi` tags will match every operation.

## Validation shape

A clean OpenAPI-leak finding includes:

1. The exact spec URL.
2. A summary of operations (count + examples of sensitive ones).
3. List of hidden environments leaked via `servers`.
4. List of unauthenticated operations.
5. Probe results for at least one previously-unknown operation that returns sensitive data.
6. Whether deprecated / internal / debug operations are reachable.

## False positives

- Spec is intentionally public (publicly-documented API; check if it matches the official docs).
- Spec is exhaustive but every operation enforces strict auth + scope + RoE-respected access.
- Hidden operations all return 401 / 403 / 404 -- no authorization surface gained.
- `servers` array points only at the production host.
- Spec is served only over an authenticated endpoint (rare but valid).

## Hand-off

```
Hidden auth schemes / debug ops      -> probe each with /skill information_disclosure
Unauth operations                     -> matrix-test against all data classes
JWT bearer auth in spec               -> /skill jwt_attacks
OAuth in spec                         -> /skill oauth_oidc
GraphQL endpoint listed in spec       -> /skill graphql
WebSocket endpoint hinted at          -> /skill websocket_security
Mass parameter discovery              -> built-in mass_assignment skill
Spec contains x-rate-limit / WAF rules -> note the limits but do not probe DoS
```

## Pro tips

- Always check `/openapi.yaml` AND `/openapi.json`; some servers only emit YAML.
- Older Swagger 2.0 specs use `swagger`, `host`, `basePath`, `securityDefinitions`. OpenAPI 3.0+ uses `openapi`, `servers`, `components.securitySchemes`. Parse both.
- The richest signal is `servers[].url` -- staging environments typically lack the production hardening.
- Spec drift between v1 / v2 / internal is the most common bug-bounty win: an operation deprecated in v2 is still callable in v1.
- `examples` / `default` values in the spec sometimes contain real test credentials. Search the spec body for `password`, `token`, `key`, `secret`.
- For Swagger UI exposure: try `/swagger?spec=<attacker>.json`. If the URL parameter is honored, you can stage a spec that triggers stored XSS in the rendered docs.
- Treat the spec as a parameter-fuzz seed list; hand to `execute_arjun` to find params the spec doesn't declare.
