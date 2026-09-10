"""
RedAmon Attack Skill Classification Prompt

LLM-based classification of user intent to select the appropriate attack skill and phase.
Determines both the attack methodology AND the required phase (informational/exploitation).
Dynamically includes only ENABLED skills in the classification prompt.
"""

from project_settings import get_enabled_builtin_skills, get_enabled_user_skills, get_setting


# =============================================================================
# BUILT-IN SKILL SECTIONS (included when the skill is enabled)
# =============================================================================

_CVE_EXPLOIT_SECTION = """### cve_exploit — CVE (MSF)
- Exploit known CVE vulnerabilities directly against a service using Metasploit Framework (MSF) modules
- Keywords: CVE-XXXX, exploit, RCE, vulnerability, pwn, hack, metasploit
"""

_BRUTE_FORCE_SECTION = """### brute_force_credential_guess
- Password guessing / credential attacks using Hydra against login services (SSH, FTP, MySQL, RDP, SMB, etc.)
- Key distinction: choose this ONLY when the win genuinely requires DISCOVERING a valid secret (a real username+password that exists and must be found). A login form that can instead be defeated by the SHAPE or TYPE of the request, or by any comparison / trust / logic flaw in how the app checks credentials, is an authentication BYPASS -> use access_control. Credential guessing is a LAST resort, only after the authentication-logic bypass has been tried and recorded.
- Keywords: brute force, crack password, dictionary attack, wordlist, password spray, guess password, credential attack
"""

_PHISHING_SECTION = """### phishing_social_engineering
- Attack where a target user must execute, open, click, or install something (payload, document, link, one-liner)
- Includes: msfvenom payloads, document-based payloads, web delivery, email delivery, handler setup
- Key distinction: target user runs artifact on THEIR machine (vs cve_exploit which hits a service directly)
- Keywords: payload, reverse shell, msfvenom, payload delivery, phishing, document payload, handler
"""

_DOS_SECTION = """### denial_of_service
- Attacks that DISRUPT service availability rather than gaining access or stealing data
- Includes: DoS modules, flooding, slowloris, resource exhaustion, crash exploits
- Key distinction: goal is DISRUPTION/CRASH/UNAVAILABILITY — no shell, no credentials, no data theft
- Keywords: dos, denial of service, crash, disrupt, availability, slowloris, flood, exhaust, stress test, take down, knock offline, overwhelm
"""

_SQLI_SECTION = """### sql_injection — SQL Injection
- SQL injection testing against web applications using SQLMap and manual techniques
- Includes: error-based, union-based, blind boolean, blind time-based, out-of-band (OOB/DNS exfiltration)
- Key distinction: injecting SQL into application parameters to extract data or gain access
- Keywords: SQL injection, SQLi, sqlmap, database dump, union select, blind injection, WAF bypass, authentication bypass
"""

_XSS_SECTION = """### xss — Cross-Site Scripting (XSS)
- XSS testing against web applications using dalfox, kxss, Playwright DOM analysis, and manual context-aware payloads
- Includes: reflected XSS, stored XSS, DOM-based XSS, blind XSS via OOB callbacks, CSP bypass
- Key distinction: injecting JavaScript that executes in a victim's browser context (vs sql_injection which targets the DB, vs ssrf which targets the backend)
- Keywords: XSS, cross-site scripting, reflected XSS, stored XSS, DOM XSS, blind XSS, dalfox, payload encoding, CSP bypass, innerHTML, event handler, script injection
"""

_HTTP_SMUGGLING_SECTION = """### http_request_smuggling — HTTP Request Smuggling / Desync
- Desynchronize a FRONT tier (reverse proxy / load balancer / CDN / cache) and the BACK-END app so a smuggled request is interpreted differently by each — reaching endpoints the front tier blocks, poisoning another user's request, or bypassing front-enforced access controls
- Includes: CL.TE, TE.CL, TE.TE (obfuscated Transfer-Encoding), CL.0 / request-queue poisoning, cache poisoning via smuggling
- Key distinction: the flaw is in how a CHAIN of HTTP processors (a proxy/cache in FRONT of a distinct app server) disagree on where one request ends — not a single app parameter (SQLi/XSS) or a URL fetcher (SSRF)
- Keywords: request smuggling, HTTP desync, CL.TE, TE.CL, Transfer-Encoding, Content-Length, chunked, front-end/back-end, reverse proxy, load balancer, request queue poisoning, connection reuse
"""

_SSRF_SECTION = """### ssrf — Server-Side Request Forgery (SSRF)
- SSRF testing against web applications: forcing the server to make requests to internal services, cloud metadata endpoints, or arbitrary destinations the attacker cannot reach directly
- Includes: classic / blind / semi-blind SSRF, cloud metadata pivots (AWS IMDS, GCP/Azure metadata), protocol smuggling (gopher, file, dict), DNS rebinding, URL parser confusion, redirect chains, internal port scanning via SSRF, RCE chains via Redis/FastCGI/Docker
- Key distinction: the server fetches an attacker-controlled URL (vs sql_injection which manipulates DB queries, vs xss which executes JS in a victim browser, vs phishing which builds artifacts for a target user)
- Keywords: SSRF, server-side request forgery, internal request, cloud metadata, IMDS, IMDSv2, gopher, redirect bypass, DNS rebinding, internal SSRF, blind SSRF, webhook abuse, URL fetcher, link preview, parser differential, CRLF injection, OAST callback
"""

_RCE_SECTION = """### rce — Remote Code Execution (RCE) / Command Injection
- RCE testing against web applications and services: forcing the target to execute attacker-controlled code via OS command injection, server-side template injection (SSTI), insecure deserialization, dynamic eval / expression languages, media + document pipelines, or SSRF-to-RCE chains
- Includes: command injection (commix), SSTI across Jinja2/Twig/Freemarker/Velocity/EJS/Thymeleaf (sstimap), Java deserialization gadget chains (ysoserial: URLDNS, CommonsCollections, Spring), PHP unserialize, Python pickle, Ruby Marshal, .NET ViewState, OGNL/SpEL/MVEL injection, ImageMagick/Ghostscript/ExifTool/LaTeX pipeline RCE, Log4Shell-style JNDI lookups, Spring4Shell, Struts S2-045, container/k8s escape probes, OOB DNS oracles via interactsh
- Key distinction: code or shell commands execute on the SERVER (vs xss which runs JS in a victim browser, vs sql_injection which only injects SQL into a DB, vs ssrf which forces outbound HTTP fetches without code execution, vs cve_exploit which uses Metasploit modules against pre-known CVEs in network services, vs path_traversal which only reads files unless escalated via a wrapper-and-log-poisoning chain)
- Keywords: RCE, remote code execution, command injection, code injection, shell injection, SSTI, server-side template injection, template injection, deserialization, gadget chain, ysoserial, commix, sstimap, eval, exec, system command, OGNL, SpEL, MVEL, log4shell, log4j, spring4shell, struts, ImageMagick, ImageTragick, Ghostscript, ExifTool, JNDI, picture upload RCE, Jinja2 SSTI, Freemarker SSTI, Twig SSTI, pickle RCE, container escape, docker.sock
"""

_PATH_TRAVERSAL_SECTION = """### path_traversal — Path Traversal / LFI / RFI
- File-disclosure testing against web applications: coercing the target to read or include files outside the intended root via `../` traversal, encoded variants, normalisation gaps, PHP wrappers (`php://filter`, `data://`, `expect://`, `zip://`), log poisoning, remote inclusion (RFI) via `http://`/`ftp://` schemes, and archive-extraction (Zip Slip)
- Includes: classic path traversal, Local File Inclusion (LFI), Remote File Inclusion (RFI), PHP wrapper-driven source disclosure, log poisoning to RCE, /proc and cloud-credential file reads, parser/normalisation mismatches across nginx + backend (`..;/`, `%252f` double-decode), Windows UNC and absolute-path acceptance, archive entries with `../` or symlinks that escape the extraction directory
- Key distinction: the goal is to READ (or write via Zip Slip) a file outside the intended root (vs sql_injection which targets the database, vs xss which executes JS in a browser, vs ssrf which forces outbound HTTP fetches without filesystem access, vs rce which runs code on the server unless this skill chains LFI + log poisoning to escalate, vs cve_exploit which uses Metasploit modules against pre-known CVEs)
- Keywords: path traversal, directory traversal, LFI, local file inclusion, RFI, remote file inclusion, file inclusion, file read, arbitrary file read, ../, %2e%2e%2f, php://filter, data://, expect://, zip://, file://, log poisoning, /etc/passwd, /etc/hosts, web.config, win.ini, wp-config, .env disclosure, SecLists fuzz file, nginx alias bypass, ..;/, double-decode, Zip Slip, archive extraction, tarslip, symlink archive
"""

_UNCLASSIFIED_SECTION = """### <descriptive_term>-unclassified
- ANY exploitation request that does NOT clearly fit the enabled attack skills above
- The agent has no specialized workflow for these — it will use available tools generically
- **Key distinction from phishing:** the attacker directly interacts with a SERVICE/APPLICATION, NOT generating a payload for a target user to execute
  - "Try to abuse the bulk-export endpoint" → unclassified (attacker sends crafted input to a web service)
  - "Generate a reverse shell payload" → phishing (attacker creates a file for a target user to execute)
- **Key distinction from sql_injection:** if the request is specifically about SQL injection, use the `sql_injection` skill instead
- **Key distinction from xss:** if the request is specifically about XSS, cross-site scripting, or JavaScript injection in a browser, use the `xss` skill instead
- **Key distinction from ssrf:** if the request is specifically about SSRF, server-side request forgery, cloud metadata access, or forcing the server to make outbound requests, use the `ssrf` skill instead
- **Key distinction from rce:** if the request is specifically about command injection, SSTI, deserialization gadget chains, eval / OGNL / SpEL injection, media-pipeline RCE, or any other path leading to remote CODE/SHELL execution on the server, use the `rce` skill instead
- **Key distinction from path_traversal:** if the request is specifically about path traversal, directory traversal, LFI, RFI, file inclusion, PHP wrappers (`php://filter`, `data://`, `expect://`), log poisoning, or Zip Slip / archive-extraction file writes, use the `path_traversal` skill instead
- **Key distinction from xxe:** if the request is specifically about XXE, XML external entities, an attacker-supplied DOCTYPE / ENTITY / DTD, XInclude, or an XML parser processing untrusted XML (SOAP, `.wsdl`, XML upload such as SVG / DOCX), use the `xxe` skill instead
- You MUST create a short, descriptive snake_case term followed by "-unclassified"
- Format: `<term>-unclassified` where term is 1-4 lowercase words joined by underscores
- Example values: "file_upload-unclassified", "race_condition-unclassified", "mass_assignment-unclassified"
- Keywords: file upload, privilege escalation, race conditions
- Example requests:
  - "Try to upload a web shell" -> "file_upload-unclassified"
  - "Test for a race condition on the coupon endpoint" -> "race_condition-unclassified"
"""

_ACCESS_CONTROL_SECTION = """### access_control — Broken Access Control / Authorization Bypass
- Defeating an authentication or authorization decision that has NO injection, inclusion, or template surface: reaching a resource, function, role, or object the request is not supposed to be allowed
- Includes: authentication-logic bypass at a login / credential form (defeating the credential CHECK itself by the shape or TYPE of the submitted values — input-type confusion, loose / type-juggling comparisons, and client-trusted or default auth-state logic — rather than by discovering a valid password), forced browsing / function-level access to hidden or admin endpoints, vertical + horizontal privilege escalation, IDOR / BOLA (object-level authorization via numeric/UUID/filename/token references), HTTP verb / method tampering and method-override headers, 401/403 bypass via path normalization (trailing slash, `%2e`, `%2f`, double-encoding, `..;/`) and trust headers (X-Original-URL, X-Rewrite-URL, X-Forwarded-For, X-Custom-IP-Authorization), parameter / hidden-field / cookie role tampering, mass assignment, JWT CLAIM tampering (trusting an unverified or forged claim when the signature is not properly checked - the CRYPTOGRAPHIC break of a JWT is crypto_attack), CORS and GraphQL/API authorization flaws, and multi-step business-logic bypass
- Key distinction: the goal is to defeat an ACCESS DECISION by changing the request shape (method, path form, trusted header, client-supplied role/id, token claim, or the type/presence of a submitted credential field) — NOT to inject code/SQL/templates (rce / sql_injection), run JS in a browser (xss), read files outside the web root (path_traversal), forge server-side requests (ssrf), or GUESS a valid secret (brute_force_credential_guess — that is only for when a real credential must be discovered, not for a login defeated by malformed/mistyped inputs or a comparison flaw)
- A plain login form, or an explicit "bypass the login / get in as admin" objective, belongs HERE first when the credential may not need to be guessed — test the authentication-logic bypass before assuming a password must be brute-forced
- Keywords: access control, broken access control, authorization bypass, authentication bypass, auth bypass, login bypass, login form bypass, bypass the login, type juggling, loose comparison, input type confusion, magic hash, IDOR, BOLA, insecure direct object reference, privilege escalation, forced browsing, function-level authorization, method tampering, verb tampering, HTTP method bypass, 401 bypass, 403 bypass, X-Original-URL, X-Forwarded-For bypass, trust header, hidden field, isAdmin, role tampering, mass assignment, JWT claim tampering, JWT bypass, business logic, CORS misconfiguration, GraphQL authorization
"""

_XXE_SECTION = """### xxe - XML External Entity (XXE) Injection
- Coerce a server-side XML parser that resolves external entities into reading local files, forging server-side requests (SSRF), or leaking data in-band, via error messages, or out-of-band
- Includes: classic in-band file read (`file://`), base64 source read via a PHP stream filter, error-based exfiltration through an external OR a local system DTD (parameter entities), blind out-of-band (OOB) exfiltration via a hosted DTD + callback, SSRF / cloud-metadata via entity URLs, XInclude when the DOCTYPE is stripped, content-type switching (JSON / form to XML), and XXE inside uploads (SVG, DOCX / XLSX / OOXML, SAML)
- Key distinction: the flaw is in how the server PARSES an attacker-supplied XML document (a DOCTYPE / ENTITY / DTD it processes), NOT a URL/host PARAMETER the app fetches (that is ssrf), NOT a PATH parameter file read (that is path_traversal), NOT code execution on the server (that is rce), and NOT a database query (that is sql_injection)
- Keywords: XXE, XML external entity, XML injection, DOCTYPE, ENTITY, external entity, DTD, parameter entity, XInclude, blind XXE, out-of-band XXE, external DTD, SOAP XXE, wsdl, SVG upload XXE, OOXML XXE, docx XXE, SAML XXE
"""

_CRYPTO_ATTACK_SECTION = """### crypto_attack - Cryptographic Attacks
- Break a cryptographic construction the app trusts: DECRYPT or FORGE an attacker-controllable ciphertext, cookie, token, signature, or MAC by exploiting HOW it is encrypted, signed, hashed, or generated - not by guessing a secret and not by trusting an unverified claim
- Includes: CBC padding oracle (decrypt + forge), CBC / stream ciphertext malleability and bit-flipping, ECB block analysis (cut-and-paste, byte-at-a-time), IV / nonce misuse, stream-cipher keystream / nonce reuse (two-time pad), JWT signature attacks (alg:none, HS/RS algorithm confusion, weak-secret cracking, kid / jwk / jku key injection), hash length extension on `H(secret || message)`, HMAC / MAC forgery, RSA weaknesses (small e, shared / close primes, Wiener, Hastad, Bleichenbacher), predictable token / PRNG / seed reconstruction (LCG, Mersenne Twister, time-seeded), plus classical-cipher and multi-layer encoding breaks
- Key distinction: the flaw is in the CRYPTO itself - a decrypt / verify oracle, ciphertext malleability, a weak or forgeable key / signature, or predictable randomness lets you recover or forge the trusted value. This is NOT trusting an unverified request claim or defeating an access decision by request shape (access_control), NOT a deserialization gadget that runs code (rce), NOT SQL / template / command injection, and NOT guessing a valid login password (brute_force_credential_guess)
- If a secret is carried in an encrypted / signed / encoded token you control (a cookie, token, signature, or ciphertext parameter whose plaintext you cannot read directly), attack the token's cryptography HERE rather than trying to recover the secret indirectly (guessing or brute-forcing it, or deriving it from a side channel)
- Decisive trigger: the MOMENT the objective is gated by such an opaque / encoded / encrypted value the server decrypts or verifies, treat it as a crypto target - `switch_skill` to crypto_attack and transition to exploitation to attack its construction, rather than staying in reconnaissance to enumerate or re-fingerprint it
- Keywords: crypto, cryptography, cryptographic attack, padding oracle, CBC, ECB, block cipher, stream cipher, AES, DES, cipher, ciphertext, decrypt, encryption, IV, bit flipping, bit-flip, ciphertext malleability, keystream reuse, nonce reuse, two-time pad, XOR cipher, JWT signature, algorithm confusion, alg none, HS256, RS256, weak JWT secret, JWK injection, JKU injection, kid injection, hash length extension, length extension attack, MAC forgery, HMAC, RSA, modulus factoring, factordb, Wiener, Hastad, Fermat, Bleichenbacher, LCG, Mersenne Twister, predictable token, weak PRNG, seed prediction, weak encryption, weak cryptography
"""

# Map of built-in skill ID -> (section text, classification priority letter)
_BUILTIN_SKILL_MAP = {
    'phishing_social_engineering': (_PHISHING_SECTION, 'a', 'phishing_social_engineering'),
    'brute_force_credential_guess': (_BRUTE_FORCE_SECTION, 'b', 'brute_force_credential_guess'),
    'cve_exploit': (_CVE_EXPLOIT_SECTION, 'c', 'cve_exploit'),
    'denial_of_service': (_DOS_SECTION, 'd', 'denial_of_service'),
    'sql_injection': (_SQLI_SECTION, 'e', 'sql_injection'),
    'xss': (_XSS_SECTION, 'f', 'xss'),
    'ssrf': (_SSRF_SECTION, 'g', 'ssrf'),
    'rce': (_RCE_SECTION, 'h', 'rce'),
    'path_traversal': (_PATH_TRAVERSAL_SECTION, 'i', 'path_traversal'),
    'access_control': (_ACCESS_CONTROL_SECTION, 'j', 'access_control'),
    'http_request_smuggling': (_HTTP_SMUGGLING_SECTION, 'k', 'http_request_smuggling'),
    'xxe': (_XXE_SECTION, 'l', 'xxe'),
    'crypto_attack': (_CRYPTO_ATTACK_SECTION, 'm', 'crypto_attack'),
}

# Classification instructions for built-in skills (no priority — best match wins)
_CLASSIFICATION_INSTRUCTIONS = {
    'phishing_social_engineering': """   - **phishing_social_engineering**:
      - Is the request asking to GENERATE, CREATE, or SET UP a payload, malicious file, document, backdoor, reverse shell, one-liner, or delivery server?
      - Will the output be something a target user must execute, open, click, or install on their machine?
      - Does it mention msfvenom, handler, multi/handler, web delivery, HTA server, encoding for AV evasion?
      - Does it mention sending something via email to a target person?""",
    'brute_force_credential_guess': """   - **brute_force_credential_guess**:
      - Does the request mention password guessing, brute force, credential attacks, wordlists, or dictionary attacks?
      - Does it target a login service (SSH, FTP, MySQL, etc.) with credential-based attack?
      - Does the win REQUIRE discovering a real, valid secret that genuinely exists? If a web login could instead be defeated by the request shape or malformed/mistyped inputs or a comparison/trust flaw, classify **access_control** FIRST and fall back to brute force only after that bypass is ruled out — do not brute-force a login before its authentication-logic bypass has been tried.""",
    'cve_exploit': """   - **cve_exploit**:
      - Does the request mention a specific CVE ID or Metasploit exploit module to use DIRECTLY against a service?
      - Does it describe exploiting a service vulnerability where NO target user interaction is needed?""",
    'denial_of_service': """   - **denial_of_service**:
      - Is the goal to DISRUPT, CRASH, or make a service UNAVAILABLE (not to gain access)?
      - Does it mention DoS, denial of service, flooding, slowloris, stress test, take down, exhaust resources?
      - Is the user NOT trying to get a shell, steal data, or obtain credentials?""",
    'sql_injection': """   - **sql_injection**:
      - Does the request mention SQL injection, SQLi, database dumping, or union/blind injection?
      - Does it target a web application parameter with SQL-specific attack intent?
      - Does it mention sqlmap, WAF bypass for SQL, authentication bypass via SQL, or OOB/DNS exfiltration?""",
    'xss': """   - **xss**:
      - Does the request mention XSS, cross-site scripting, JavaScript injection, or DOM sinks?
      - Does it target a web application input/parameter with the goal of executing JS in a victim browser?
      - Does it mention reflected/stored/DOM XSS, payload encoding, CSP bypass, blind XSS callbacks, or dalfox?""",
    'ssrf': """   - **ssrf**:
      - Does the request mention SSRF, server-side request forgery, internal request, or webhook abuse?
      - Does it target a URL/host/redirect parameter with the goal of forcing the server to fetch attacker-controlled or internal destinations?
      - Does it mention cloud metadata (IMDS, 169.254.169.254, metadata.google.internal), gopher://, DNS rebinding, or internal port scanning via URL fetcher?
      - Does it describe parser confusion, redirect chains, or CRLF injection in URL parameters?""",
    'rce': """   - **rce**:
      - Does the request mention RCE, remote code execution, command injection, code injection, or shell execution on the server?
      - Does it mention server-side template injection (SSTI), Jinja2 / Twig / Freemarker / Velocity / EJS / Thymeleaf payloads?
      - Does it mention insecure deserialization, gadget chains, ysoserial, pickle, PHP unserialize, ViewState, or Marshal.load?
      - Does it mention eval / exec / OGNL / SpEL / MVEL injection, or expression-language abuse?
      - Does it mention Log4Shell / JNDI, Spring4Shell, Struts S2-045, ImageMagick / Ghostscript / ExifTool / LaTeX pipeline RCE?
      - Does it describe a path that ends in a SHELL or CODE running on the server (not just data extraction or browser-side JS)?""",
    'path_traversal': """   - **path_traversal**:
      - Does the request mention path traversal, directory traversal, LFI, RFI, file inclusion, or arbitrary file read?
      - Does it mention `../`, `%2e%2e%2f`, `..;/`, double-decode, or nginx alias bypass?
      - Does it mention PHP wrappers (`php://filter`, `data://`, `expect://`, `zip://`) or log poisoning to escalate LFI?
      - Does it mention reading sensitive files like `/etc/passwd`, `/etc/hosts`, `/proc/self/environ`, `wp-config.php`, `.env`, `web.config`, or cloud credential files?
      - Does it mention archive-extraction (Zip Slip / TarSlip), symlink-in-archive escapes, or writing files outside an extraction directory?
      - Key boundary: STOP before this skill if the goal is direct command execution -- that belongs to `rce` -- unless the request explicitly chains LFI + log poisoning to land RCE (then it stays here).""",
    'access_control': """   - **access_control**:
      - Is there an authentication / authorization wall (login prompt, `401`/`403`, "admin only" gate, a resource or object you should not be able to reach) with NO injection / inclusion / template surface?
      - Is this a plain login form or a "bypass the login / log in as admin" objective? Classify it HERE first: the flaw is often in HOW the app compares or trusts the submitted values (input-type confusion, loose or type-juggling comparison, client-trusted or default auth-state logic), defeated by the SHAPE or TYPE of the request rather than by a guessed password. Test that authentication-logic bypass before assuming credentials must be brute-forced.
      - PROXY-CHAIN CHECK: if the resource you cannot reach is an INTERNAL-ONLY virtual host, hostname, or backend whose name/authority the app itself discloses but a FRONT proxy rewrites or refuses, and recon shows a MULTI-TIER HTTP path (a reverse proxy / load balancer / cache in front of a distinct app server, betrayed by `Via` / `X-Upstream-Proxy` / differing `Server` or `X-*` headers), then the gate is enforced at the PROXY, not the app: this is a routing/desync problem — prefer `http_request_smuggling`. A login or admin panel in front of it is often a DECOY; do not sink the run into credential brute-forcing when the real wall is a proxy that rewrites the routing `Host`.
      - Would the bypass come from changing the REQUEST SHAPE — a different HTTP method/verb, a path/resource form, a trusted header, a client-supplied role/flag/id, a token claim, or the type/presence of a submitted credential field — rather than injecting a payload?
      - Does it mention access control, authorization/authentication bypass, IDOR/BOLA, privilege escalation, forced browsing, method/verb tampering, hidden fields, mass assignment, JWT tampering, CORS, or business-logic abuse?
      - Boundary: if the goal is specifically SQLi / XSS / SSRF / RCE / file read / credential guessing, use THAT skill instead — access_control is for defeating the access DECISION itself.""",
    'http_request_smuggling': """   - **http_request_smuggling**:
      - Does recon reveal a MULTI-TIER HTTP path — a reverse proxy, load balancer, CDN, or cache in FRONT of a distinct back-end app server (differing `Server`/`Via`/`X-Cache`/`X-*` proxy headers, hop-by-hop header differences, or a front tier that answers before the app)?
      - Is there a resource the FRONT tier blocks (401/403/redirect) that the back-end would serve if the request reached it directly — a front-enforced access control worth bypassing from behind?
      - Is there an INTERNAL-ONLY virtual host, hostname, or backend the app itself references (in a response header, a link, an error, or verbose output) that a DIRECT request cannot reach because the front tier rewrites the `Host` / authority? Reaching it requires smuggling a request whose `Host` / authority survives the front tier untouched — a strong smuggling tell even when a login or admin panel is the visible surface.
      - Is there a page (often reachable via weak or DEFAULT credentials) that REFLECTS the response of a SERVER-SIDE fetch the app makes to an internal host? That reflected fetch is your READ ORACLE for a response/desync: chain the default-credential foothold to reach it, then use smuggling to change what that internal fetch returns.
      - Do the two tiers appear to disagree on request framing — does the server react differently to a `Transfer-Encoding: chunked` + `Content-Length` combination, an obfuscated TE header, or trailing/pipelined bytes than a single server would?
      - Boundary: if there is only ONE HTTP server with no proxy/cache in front, or the goal is a single-parameter injection, use the matching skill instead. This skill defeats the request-boundary AGREEMENT between chained HTTP processors.""",
    'xxe': """   - **xxe**:
      - Does the request mention XXE, XML external entity, XML injection, a DOCTYPE / ENTITY / DTD, or XInclude?
      - Does the target parse attacker-supplied XML — a SOAP / XML-RPC endpoint, a `.wsdl`, an XML request body, or an upload that accepts SVG / DOCX / XLSX / SAML?
      - Is the goal to read local files, reach internal services, or exfiltrate data THROUGH the XML parser (in-band reflection, error-based, or out-of-band via an external/local DTD)?
      - Boundary: if the file read is via a PATH parameter use path_traversal; if a URL/host PARAMETER is fetched use ssrf; if code executes on the server use rce. xxe is specifically the abuse of XML entity / DTD processing.""",
    'crypto_attack': """   - **crypto_attack**:
      - Is there an attacker-controllable ciphertext, cookie, token, signature, or MAC that the server DECRYPTS or VERIFIES, where the goal is to decrypt or FORGE it by breaking the crypto (not by guessing a password and not by trusting an unchecked claim)?
      - Does the endpoint answer DIFFERENTLY for a malformed / bad-padding / bad-signature token than for a well-formed-but-wrong one (a padding or signature oracle)?
      - Does the material look like a block cipher (length a multiple of 8 / 16), ECB (repeating 16-byte blocks), a JWT (three dot-separated parts), a keyed hash / MAC trailer, an RSA n / e / c triple, or a predictable / sequential generated token?
      - Does it mention padding oracle, CBC / ECB, bit-flipping, keystream / nonce reuse, JWT alg:none / algorithm confusion / weak secret, hash length extension, RSA factoring, or predictable PRNG / token?
      - Boundary: if the win is trusting an unverified claim or a request-shape auth bypass use access_control; a deserialization gadget that runs code is rce; guessing a real password is brute_force_credential_guess.""",
}


# =============================================================================
# RUNTIME SKILL GUIDE — the SAME per-skill text step-1 shows, injected EVERY turn
# =============================================================================
# The classifier below runs ONCE, on the user's request text, before any recon,
# so in a black-box run it yields `recon-unclassified`. The real class is then
# chosen mid-run from LIVE EVIDENCE via `switch_skill` — but historically that
# runtime decision saw only bare class NAMES and fell back to priors (any
# login/401 -> sql_injection). This injects the FULL per-skill description +
# selection criteria (identical to what step-1 renders: the `_*_SECTION` from
# _BUILTIN_SKILL_MAP + the `_CLASSIFICATION_INSTRUCTIONS`) into every think turn,
# so the agent re-selects against the real discriminators. It lives in the cached
# prompt prefix, so after turn 1 it is billed at cache-read cost.
def build_skill_menu(enabled_builtins: set[str], enabled_user_skills: list[dict]) -> str:
    """Full per-skill selection text (step-1 sections + criteria) for every turn."""
    order = ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit',
             'denial_of_service', 'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal', 'access_control',
             'http_request_smuggling', 'xxe', 'crypto_attack']
    parts = [
        "## ATTACK SKILL SELECTION — re-evaluate EVERY turn\n"
        "Below is the full catalog of enabled attack classes, with the SAME description and "
        "selection criteria used to classify at session start. Match the STRONGEST evidence from "
        "the LIVE target to ONE class, then keep your active skill or `switch_skill` to the "
        "better-fitting class (switching needs no phase change).\n"
    ]
    for sid in order:
        if sid in enabled_builtins:
            section_text, _, _ = _BUILTIN_SKILL_MAP[sid]
            parts.append(section_text.rstrip())
            parts.append(_CLASSIFICATION_INSTRUCTIONS[sid])
    for skill in (enabled_user_skills or []):
        preview = skill.get('description') or skill.get('content', '')[:500]
        if not skill.get('description') and len(skill.get('content', '')) > 500:
            preview += "..."
        parts.append(f'### user_skill:{skill["id"]} — {skill["name"]}\n{preview}')
    return "\n".join(parts)


def build_classification_prompt(objective: str) -> str:
    """Build a dynamic classification prompt based on enabled skills.

    Only includes sections for enabled built-in skills and any enabled user skills.
    """
    enabled_builtins = get_enabled_builtin_skills()
    enabled_user_skills = get_enabled_user_skills()

    # RoE enforcement: exclude skills from classification when RoE prohibits them
    if get_setting('ROE_ENABLED', False):
        if not get_setting('ROE_ALLOW_DOS', False):
            enabled_builtins.discard('denial_of_service')
        if not get_setting('ROE_ALLOW_ACCOUNT_LOCKOUT', False):
            enabled_builtins.discard('brute_force_credential_guess')
        if not get_setting('ROE_ALLOW_SOCIAL_ENGINEERING', False):
            enabled_builtins.discard('phishing_social_engineering')

    # --- Header ---
    parts = [
        "You are classifying a penetration testing request to determine:\n"
        "1. The required PHASE (informational vs exploitation)\n"
        "2. The ATTACK SKILL TYPE (for exploitation requests only)\n"
    ]

    # --- Phase Types (always included) ---
    parts.append("""## Phase Types

### informational
- Reconnaissance, OSINT, information gathering
- Querying the graph database for targets, vulnerabilities, services
- Scanning and enumeration without exploitation
- Example requests:
  - "What vulnerabilities exist on 10.0.0.5?"
  - "Show me all open ports on the target"
  - "What services are running?"
  - "Query the graph for CVEs"
  - "Scan the network"
  - "What technologies are used?"

### exploitation
- Active exploitation of vulnerabilities
- Brute force / credential attacks
- Generating payloads, reverse shells, or delivery mechanisms for target user execution
- Setting up handlers, listeners, or delivery servers
- Any request that involves gaining unauthorized access
- Example requests:
  - "Exploit CVE-2021-41773"
  - "Brute force SSH"
  - "Try to crack the password"
  - "Pwn the target"
  - "Try SQL injection on the web app"
  - "Generate a reverse shell payload"
  - "Create a malicious Word document"
  - "Set up a web delivery attack"
""")

    # --- Attack Skill Types ---
    parts.append("## Attack Skill Types (ONLY for exploitation phase)\n")

    # Built-in skills (only enabled ones)
    for skill_id in ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal', 'access_control', 'xxe', 'crypto_attack']:
        if skill_id in enabled_builtins:
            section_text, _, _ = _BUILTIN_SKILL_MAP[skill_id]
            parts.append(section_text)

    # User skills — use description if available, otherwise first 500 chars of content
    for skill in enabled_user_skills:
        preview = skill.get('description') or skill['content'][:500]
        if not skill.get('description') and len(skill['content']) > 500:
            preview += "..."
        parts.append(f'### user_skill:{skill["id"]}\n'
                     f'- User-defined attack skill: **{skill["name"]}**\n'
                     f'- Skill description:\n{preview}\n')

    # Unclassified (always included)
    parts.append(_UNCLASSIFIED_SECTION)

    # --- User Request ---
    parts.append(f"## User Request\n{objective}\n")

    # --- Classification Instructions ---
    parts.append("## Instructions\nClassify the user's request:\n")
    parts.append("1. First determine the REQUIRED PHASE:\n"
                 '   - Is this a reconnaissance/information gathering request? -> "informational"\n'
                 '   - Is this an active attack/exploitation request? -> "exploitation"\n')

    parts.append("2. Determine the AGENT SKILL TYPE that **best matches** the request — regardless of phase. "
                 "Even informational requests have a skill type (e.g., 'scan for SQLi' → sql_injection, "
                 "'brute force SSH' → brute_force_credential_guess). Pick the one whose criteria fit most closely:\n")

    # Built-in skill classification criteria
    builtin_skill_ids = ['phishing_social_engineering', 'brute_force_credential_guess', 'cve_exploit', 'denial_of_service', 'sql_injection', 'xss', 'ssrf', 'rce', 'path_traversal', 'access_control', 'xxe', 'crypto_attack']
    for skill_id in builtin_skill_ids:
        if skill_id in enabled_builtins:
            parts.append(_CLASSIFICATION_INSTRUCTIONS[skill_id])

    # User skills classification criteria
    for skill in enabled_user_skills:
        parts.append(f'   - **user_skill:{skill["id"]}** ("{skill["name"]}"):\n'
                     f'      - Does the request match the workflow described in the "{skill["name"]}" skill?')

    # Unclassified
    parts.append("   - **<descriptive_term>-unclassified**:\n"
                 "      - Does the request describe a specific attack technique that doesn't match any of the above?\n"
                 "      - For general reconnaissance with no specific attack intent (e.g., 'show attack surface', "
                 "'what vulnerabilities exist'), use **recon-unclassified**")

    # A vague "hack the target" should start with surface discovery, NOT jump straight
    # into the Metasploit/CVE workflow (which assumes a known-CVE target). Prefer
    # recon-unclassified when it is available; only fall back to cve_exploit if recon
    # is somehow not an enabled path.
    default_type = "recon-unclassified"
    parts.append(f'\n   If truly unclear (e.g., vague "hack the target"), default to "{default_type}" '
                 '(gather the attack surface first, then reclassify to a specific skill).\n')

    parts.append("3. Extract TARGET HINTS from the request (best-effort, used for graph linking):\n"
                 '   - target_host: IP address or hostname mentioned (e.g., "10.0.0.5", "www.example.com"). null if none found.\n'
                 '   - target_port: port number mentioned (e.g., 8080, 443). null if none found.\n'
                 '   - target_cves: list of CVE IDs mentioned (e.g., ["CVE-2021-41773"]). Empty list if none found.\n')

    # --- Build valid attack_path_type values for JSON schema ---
    valid_types = []
    for skill_id in builtin_skill_ids:
        if skill_id in enabled_builtins:
            valid_types.append(f'"{skill_id}"')
    for skill in enabled_user_skills:
        valid_types.append(f'"user_skill:{skill["id"]}"')
    valid_types.append('"<descriptive_term>-unclassified"')

    parts.append(f"""Output valid JSON matching this schema:

```json
{{{{
  "required_phase": "informational" | "exploitation",
  "attack_path_type": {' | '.join(valid_types)},
  "confidence": 0.0-1.0,
  "reasoning": "Brief explanation of the classification",
  "detected_service": "ssh" | "ftp" | "mysql" | "mssql" | "postgres" | "smb" | "rdp" | "vnc" | "telnet" | "tomcat" | "http" | null,
  "target_host": "10.0.0.5" | "www.example.com" | null,
  "target_port": 8080 | null,
  "target_cves": ["CVE-2021-41773"] | []
}}}}
```

Notes:
- `required_phase` determines if this is reconnaissance ("informational") or active attack ("exploitation")
- `attack_path_type` MUST always be set — it identifies which agent skill workflow to use, regardless of phase
- For general recon with no specific attack technique, use "recon-unclassified"
- For unclassified attack techniques, use a descriptive term followed by "-unclassified" (e.g., "ssrf-unclassified", "file_upload-unclassified")
- `detected_service` should only be set for brute_force_credential_guess, null otherwise
- `confidence` should be 0.9+ if the intent is very clear, 0.6-0.8 if somewhat ambiguous
- `target_host`, `target_port`, `target_cves` are best-effort extraction — null/empty if not mentioned""")

    return "\n".join(parts)


# Keep backward-compatible constant for any code that still references it directly
# (uses all skills enabled as default)
ATTACK_PATH_CLASSIFICATION_PROMPT = None  # Use build_classification_prompt() instead
