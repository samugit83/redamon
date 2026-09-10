---
name: OAuth 2.0 / OIDC
description: Reference for OAuth 2.0 and OpenID Connect attacks covering flow selection, redirect-URI abuse, PKCE downgrades, state/nonce gaps, mix-up, nOAuth, and refresh-token replay against black-box endpoints.
---

# OAuth 2.0 / OIDC Attacks

Tactical reference for testing OAuth 2.0 and OpenID Connect flows: redirect-URI strictness, `state`/`nonce` enforcement, PKCE downgrade, IdP mix-up, nOAuth attribute hijack, refresh-token rotation, and silent-account-link abuse. Pull this in when you have an OAuth/OIDC-protected target and need a flow map, the right metadata endpoints, or a probe matrix per spec defect.

> Black-box scope: every probe assumes you can drive the flow through HTTP(S) and a browser. There is no source-code analysis step. For pure JWT signature attacks, see `/skill jwt_attacks`.

## Tool palette

| Action | Tool | Notes |
|---|---|---|
| Drive the auth code / device / PKCE flow | `execute_playwright` | Capture the full redirect chain, copy `code`, `state`, `nonce`. |
| Replay token endpoint requests | `execute_curl` | Always send `-i` to capture status + headers. |
| Tamper with tokens / JWTs returned | `kali_shell jwt_tool` | See `/skill jwt_attacks` for header / claim mangling. |
| OOB callback for redirect or hostname testing | `kali_shell interactsh-client` | Use as the attacker `redirect_uri` host. |
| Pull captured tokens from the graph | `query_graph` | "Return endpoints/responses where Set-Cookie includes `oauth` or response body contains `access_token`." |
| Fetch metadata | `execute_curl` | `/.well-known/openid-configuration`, `/.well-known/oauth-authorization-server`. |

## Reconnaissance

Always pull provider metadata before probing.

```
execute_curl url: "https://target.tld/.well-known/openid-configuration"
execute_curl url: "https://target.tld/.well-known/oauth-authorization-server"
```

Useful keys to record:

| Field | Use |
|---|---|
| `issuer` | What `iss` claim must equal |
| `authorization_endpoint` | Where `/authorize` lives |
| `token_endpoint` | Where to redeem code / refresh |
| `jwks_uri` | Signing keys for ID/access tokens |
| `introspection_endpoint` | Token introspection (sometimes anonymous) |
| `revocation_endpoint` | Refresh / access revoke |
| `response_types_supported` | `code`, `token`, `id_token` combos accepted |
| `grant_types_supported` | `authorization_code`, `refresh_token`, `client_credentials`, `password`, `device_code`, `urn:ietf:params:oauth:grant-type:jwt-bearer` |
| `code_challenge_methods_supported` | `S256` (good), `plain` (downgradable) |
| `token_endpoint_auth_methods_supported` | `client_secret_basic`, `client_secret_post`, `private_key_jwt`, `none` |
| `subject_types_supported` | `public` vs `pairwise` |
| `claims_supported` | What user attributes may show up in ID token |
| `id_token_signing_alg_values_supported` | Watch for `none` or `HS256` next to `RS256`/`ES256` |

Map every relying party (RP), every IdP, and every resource server. Mix-up and audience-confusion attacks live in those edges.

## Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive the flow probes from the recorded redirect chain and token exchanges instead of rebuilding them by hand. proxy_brain tools only see traffic that went through the capture proxy, so drive the login (`execute_playwright` or the browser) through it first.

- Pull flow secrets: `redamon.grep("access_token")`, `redamon.grep("code=")`, and `redamon.grep("state=")` extract the `code`, `state`, `nonce`, and issued tokens from captured responses / redirects; `redamon.search({"q":"token"})` locates the `/token` exchange transaction.
- Code single-use test: `redamon.replay(<token_txn>, {})` re-sends the captured `/token` POST verbatim a second time. A second 200 with a fresh access token proves the authorization code is not single-use (mirrors the Validation script below, without rebuilding the body).
- Client / redirect binding: `redamon.replay(<token_txn>, {"body":"grant_type=authorization_code&code=<code>&client_id=<other_client>&redirect_uri=https://target.tld/cb&code_verifier=<v>"})` tests whether the code is bound to the original `client_id` and `redirect_uri`.
- Refresh-token reuse: replay a captured refresh exchange twice, or after logout, with `redamon.replay(<refresh_txn>, {})` to detect missing rotation / revocation.
- `redamon.diff(<first_exchange>, <replayed_exchange>)` shows whether the second attempt succeeded; `redamon.to_curl(id)` renders the exchange for the report.

Caveat: redamon.replay pins host/scheme/port to the origin, so the redirect-URI interception probes that require an attacker host, and any browser-driven consent step, still need execute_playwright / execute_curl. The token endpoint host is fixed to the captured origin.

## Flow cheatsheet

| Flow | Use case | Key probes |
|---|---|---|
| Authorization Code + PKCE | Public clients (SPA, mobile), confidential web | Redirect URI strictness, PKCE downgrade, state/nonce, code reuse |
| Authorization Code (no PKCE) | Legacy confidential web | Same as above plus client secret leak / rotation |
| Implicit (`response_type=token`) | Deprecated; some legacy SPAs | Token in fragment is logged in browser history; CSP/referrer leaks |
| Hybrid (`response_type=code id_token`) | Microsoft Entra, complex flows | Multi-token validation gaps |
| Resource Owner Password Grant | Legacy "first-party" apps | Password leak to client; brute force |
| Client Credentials | Service-to-service | Stolen client secret = full scope |
| Device Code | TVs, CLI | Phishing the verification URI; long-lived `device_code` |
| JWT Bearer (RFC 7523) | Federated trust | Spoofed assertions; `aud`/`iss` confusion |
| Refresh Token | Long sessions | Reuse detection, family invalidation |
| OIDC ID Token | RP login | Signature, audience, nonce, attribute mapping |

## Probe matrix

### Redirect URI

| Probe | Hint at |
|---|---|
| `redirect_uri=https://attacker.tld/cb` | No allowlist |
| `redirect_uri=https://target.tld.attacker.tld/cb` | Suffix-match instead of exact |
| `redirect_uri=https://target.tld@attacker.tld/cb` | Userinfo confusion in URL parsing |
| `redirect_uri=https://target.tld/cb#@attacker.tld/cb` | Fragment-based redirect smuggling |
| `redirect_uri=https://target.tld/cb/../../callback` | Path traversal allowed |
| `redirect_uri=https://target.tld/cb?next=https://attacker.tld` | Open redirect chain on the callback |
| `redirect_uri=javascript:alert(1)` | Scheme allowlist gap (rare but devastating in mobile WebView) |
| `redirect_uri=http://target.tld/cb` (downgrade from https) | TLS downgrade tolerated |
| Drop the parameter entirely | Server uses a default that may differ from registration |

The provider metadata may hint at strictness (`request_uri_parameter_supported`, `require_request_uri_registration`).

### `state` (CSRF) and `nonce` (replay)

| Probe | Outcome if vulnerable |
|---|---|
| Strip `state` | Login CSRF; attacker logs the victim into the attacker's session |
| Replay an old `state` | Predictable / reused state |
| Strip `nonce` | ID-token replay |
| Reuse a known `nonce` from a captured ID token | Replay accepted |

```
execute_playwright script: |
  page.goto("https://target.tld/login")
  # follow to /authorize, then strip state in the URL bar before completing
```

### PKCE

| Probe | Outcome |
|---|---|
| Submit `code_challenge_method=plain` and `code_challenge=verifier` | Plain accepted -> downgrade |
| Omit `code_challenge` entirely | Public client without PKCE is a cardinal sin |
| Swap `code_verifier` at the token endpoint | Verifier not actually checked |
| Reuse a `code_challenge` across two flows | Replayability |

### Authorization code

| Probe | Outcome |
|---|---|
| Replay the same `code` after a successful exchange | Single-use not enforced |
| Submit code with a different `client_id` | Client binding missing |
| Submit code with a different `redirect_uri` than the one in `/authorize` | Redirect-URI binding missing |
| Submit code over HTTP after issuance over HTTPS | Transport downgrade tolerated |

### Token endpoint

| Probe | Outcome |
|---|---|
| Send `client_secret` for confidential client over HTTP | Secret leak via TLS downgrade |
| Send `none` auth (`client_id` only) | Public-client mode left enabled |
| Replay a refresh token after rotation | Reuse detection missing |
| Use a refresh token from a logged-out session | Logout does not revoke |
| Swap `grant_type=password` against an OIDC server that should not allow it | Legacy grant left enabled |

### IdP mix-up

The mix-up attack: attacker registers their own RP at the same IdP, lures the victim, and then induces the victim to send the IdP's authorization code or token to the legitimate RP, which redeems it on the victim's behalf or vice versa. Indicators:

- The RP does not bind responses to the issuer (no `iss` parameter, missing `iss` in token response per RFC 9207).
- The RP supports multiple IdPs and routes based on attacker-controlled state (form field, cookie).
- The RP fetches the IdP's metadata on each request from a parameter the attacker can influence.

### nOAuth attribute hijack

Some IdPs (notably Entra ID multi-tenant) let a tenant admin set `email` or `preferred_username` to any value, including `victim@othertenant.com`. If the RP keys local accounts on `email` rather than the immutable `sub`, the attacker creates an OAuth tenant, sets the victim's email, signs in, and lands in the victim's local account.

| Probe | Outcome |
|---|---|
| Register a tenant; set `email`/`preferred_username` to a known target user; complete OAuth | Account hijack via attribute confusion |

Reproduction is environment-specific; the test is mostly **read the RP's account-link logic by behavior**: do two separately-IdP-authenticated users end up sharing the same local account when their `email` matches?

### Silent account linking

If the RP creates a local account for any successful federated sign-in and merges it with an existing one when an attribute matches (commonly `email`), unsolicited account linking lets the attacker hijack any unverified email.

```
1. Attacker registers victim@target.tld at the RP locally.
2. Attacker signs in via an IdP that does not verify email ownership and presents email=victim@target.tld.
3. The RP "links" the federated identity to the local account.
4. Attacker logs in via the IdP and inherits everything in the local account.
```

### Device authorization grant

| Probe | Outcome |
|---|---|
| Initiate device code, send the verification URL to a victim, wait for them to approve | Phishing without credentials |
| Replay device codes after the polled interval | Code reuse |
| Probe `interval` and `expires_in` for excessively long values (>15 min) | Long phishing window |

### Logout / SLO

| Probe | Outcome |
|---|---|
| Hit `/logout` then replay the access token | No revocation |
| Hit `/logout` then replay refresh | Refresh family not invalidated |
| Send `id_token_hint` for a different user | RP-initiated logout binds incorrectly |
| Front-channel logout URL not validated | Logout CSRF / log-bombing |

### ID token specifics

In addition to JWT-level attacks (see `/skill jwt_attacks`), validate at the OIDC layer:

- `iss` exactly equals the metadata `issuer` for the IdP that issued the token.
- `aud` contains the RP's `client_id`. If `aud` is an array, every entry should be an expected one.
- `azp` (authorized party) is checked when `aud` has multiple values.
- `nonce` echoes back what the RP sent.
- `auth_time` and `acr` / `amr` claims are honored when the RP demands MFA / step-up.
- `at_hash` (when present) matches the access token; mismatched at_hash indicates token-pair tampering.

## Cross-flow chains

| Chain | Steps |
|---|---|
| XSS -> token theft -> cross-service replay | XSS in RP -> steal token from `localStorage` -> replay against any service that does not enforce `aud` |
| SSRF -> JWKS pin bypass | SSRF reaches an internal JWKS endpoint -> sign with a key the gateway also trusts |
| Host header poisoning -> redirect_uri poisoning | Cache or routing keyed on Host -> attacker captures the auth code |
| Account link -> ATO | Silent linking via unverified email or via nOAuth attribute set |
| Device code phishing -> long-lived refresh | Victim approves device code -> attacker holds refresh for hours/days |
| OIDC mix-up -> code redemption hijack | Victim's code redeemed at attacker-chosen RP, or vice versa |

## Evidence shape

A clean OAuth/OIDC finding includes:

1. The exact request that started the flow (with all params).
2. The redirect chain (capture from Playwright or browser dev tools).
3. The forged or stripped value (e.g. removed `state`, swapped `redirect_uri`).
4. The resulting access token / ID token, decoded.
5. A privileged request that succeeded with the forged token.
6. A baseline failed request with no token to prove the auth gate exists at all.

## Hardening reference

- Pin redirect URIs to exact strings; reject mismatches even by trailing slash.
- Require `S256` PKCE on every public client. Reject `plain`. Drop client-credentials grant unless explicitly needed.
- Validate `state` and `nonce` server-side. Tie them to a cryptographically signed cookie or session, not to a client-side store.
- Use the `iss` parameter in authorization responses (RFC 9207) to defeat mix-up.
- Bind authorization codes to the issuing client and redirect URI; reject reuse (single-use, short TTL).
- Rotate refresh tokens on every use with reuse detection; on detection, revoke the entire token family.
- Use the immutable `sub` claim plus `iss` as the federated identity key. Never key on `email` / `preferred_username` / `name` for account lookup.
- Require email verification before linking federated identities to local accounts.
- Pin `alg` per `kid` server-side; reject `alg=none` and `HS256` when the IdP advertises asymmetric keys.
- Bind tokens to the client with DPoP or mTLS where the threat model warrants.
- For device flow, keep the user-visible `user_code` short-lived (`<= 5 min`) and rate-limit polling.

## Severity guide

- **Critical**: redirect-URI bypass that allows code/token interception; nOAuth or silent linking that grants arbitrary account takeover; PKCE downgrade leading to public-client code interception.
- **High**: missing `state` enabling login CSRF; refresh-token reuse without detection; ID-token replay against an API.
- **Medium**: `code_challenge_method=plain` accepted but no usable interception path proven; long-lived device codes; missing `iss` parameter in authorization response (mix-up risk only).
- **Low**: front-channel logout without validation; weak `acr`/`amr` enforcement.

## Validation script (token endpoint sanity)

```
execute_code language: python
import requests
TOKEN_ENDPOINT = "https://target.tld/oauth2/token"
data = {
    "grant_type": "authorization_code",
    "code": "<captured_code>",
    "redirect_uri": "https://target.tld/cb",
    "client_id": "<client_id>",
    "code_verifier": "<verifier>",
}
r = requests.post(TOKEN_ENDPOINT, data=data, timeout=10)
print(r.status_code, r.headers.get("Content-Type"))
print(r.text[:2000])
```

Replay the same body twice. A second 200 with a fresh access token proves the code is **not** single-use.
