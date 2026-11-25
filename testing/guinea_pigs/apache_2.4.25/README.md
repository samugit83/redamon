# Vulnerable Apache 2.4.25 - CVE-2017-3167 / CVE-2017-3169

Vulnerable Apache server for testing authentication bypass and NULL pointer dereference.

> **WARNING**: Intentionally vulnerable - for authorized testing only.

## Vulnerabilities

| CVE | Description | CVSS | Impact |
|-----|-------------|------|--------|
| CVE-2017-3167 | `ap_get_basic_auth_pw()` auth bypass | 9.8 | Authentication bypass |
| CVE-2017-3169 | `mod_ssl` NULL pointer dereference | 7.5 | DoS |

## EC2 Deployment (One Command)

### 1. Launch EC2
- **AMI**: Amazon Linux 2023 or Ubuntu 22.04
- **Type**: t2.micro
- **Security Group**: SSH (22) + Custom TCP (8080) - your IP only

### 2. Deploy (first time or any update)

```bash
# Copy entire folder to EC2
scp -i ~/.ssh/guinea_pigs.pem -r apache_2.4.25 ubuntu@15.160.68.117:~/apache

# Run setup
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "bash ~/apache/setup.sh"
```

### 3. Wipe & Clean (remove everything)

```bash
# Stop container, remove images, volumes, and all Docker data
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose down && sudo docker system prune -a -f --volumes"
```

---

## Test Vulnerability

```bash
# CVE-2017-3167 - Authentication bypass
# The ap_get_basic_auth_pw() function allows third-party modules
# to bypass authentication when used incorrectly

# Test protected admin area (should require auth)
curl -v "https://gpigs.devergolabs.com/admin/"

# CVE-2017-3169 - NULL pointer dereference (DoS)
# Malformed HTTP/HTTPS requests can crash the server
```

---

## Metasploit (via RedAmon Kali Container)

```bash
# Enter your own Kali sandbox with Metasploit (or open the Kali terminal in the Red Zone);
# list the sandboxes with: docker ps --filter label=redamon.sandbox=1
docker exec -it redamon-kali-<key>-<instance> msfconsole

# Search for CVE-2017-3167 module
msf6 > search CVE-2017-3167

# Search for Apache 2.4.25 related modules
msf6 > search apache 2.4.25

# Use auxiliary scanner for testing
msf6 > use auxiliary/scanner/http/apache_mod_cgi_bash_env
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > set RHOSTS gpigs.devergolabs.com
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > set RPORT 443
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > set SSL true
msf6 auxiliary(scanner/http/apache_mod_cgi_bash_env) > run
```

---

## AWS Target Group Health Check

| Setting | Value |
|---------|-------|
| **Path** | `/health` |
| **Port** | `8080` |
| **Protocol** | `HTTP` |
| **Success codes** | `200` |
