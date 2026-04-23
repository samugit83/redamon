# Guinea Pigs - Vulnerable Test Servers

Intentionally vulnerable servers for security testing and exploitation practice.

> **WARNING**: These are intentionally vulnerable systems. Deploy only in isolated environments for authorized testing.

---

## Available Guinea Pigs

| Folder | Version | CVEs | Description |
|--------|---------|------|-------------|
| `apache_2.4.49` | Apache 2.4.49 | CVE-2021-41773, CVE-2021-42013 | Path traversal + RCE |
| `apache_2.4.25` | Apache 2.4.25 | CVE-2017-3167, CVE-2017-3169 | Auth bypass + DoS |
| `node_serialize_1.0.0` | Node.js 8.x + node-serialize 0.0.4 | CVE-2017-5941 | Deserialization RCE |

Each folder contains its own `README.md` with deployment commands, wipe/clean instructions, exploitation steps, and Metasploit usage.

---

## EC2 Info

| Setting | Value |
|---------|-------|
| **IP** | 15.160.68.117 |
| **URL** | https://gpigs.devergolabs.com |
| **Port** | 8080 |
| **Health Check** | `/health` |
