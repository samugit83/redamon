# Guinea Pigs - Vulnerable Test Servers

Intentionally vulnerable Apache servers for security testing and exploitation practice.

> **WARNING**: These are intentionally vulnerable systems. Deploy only in isolated environments for authorized testing.

---

## Available Versions

| Folder | Version | CVEs | Description |
|--------|---------|------|-------------|
| `apache_2.4.49` | Apache 2.4.49 | CVE-2021-41773, CVE-2021-42013 | Path traversal + RCE |
| `apache_2.4.25` | Apache 2.4.25 | CVE-2017-3167, CVE-2017-3169 | Auth bypass + DoS |

---

## Deployment Commands

### First Time Setup (any version)

```bash
# From guinea_pigs folder, copy version to EC2
scp -i ~/.ssh/guinea_pigs.pem -r <VERSION_FOLDER> ubuntu@15.160.68.117:~/apache

# Run setup (installs Docker, builds container)
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "bash ~/apache/setup.sh"
```

### Switch to Different Version

```bash
# Stop current version
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose down"

# Copy new version (overwrites existing)
scp -i ~/.ssh/guinea_pigs.pem -r <NEW_VERSION_FOLDER> ubuntu@15.160.68.117:~/apache

# Build and start new version
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose build --no-cache && sudo docker-compose up -d"
```

### Update Current Version (after code changes)

```bash
# Copy updated folder
scp -i ~/.ssh/guinea_pigs.pem -r <VERSION_FOLDER> ubuntu@15.160.68.117:~/apache

# Rebuild and restart
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose down && sudo docker-compose build --no-cache && sudo docker-compose up -d"
```

---

## Quick Examples

### Deploy Apache 2.4.49 (Path Traversal RCE)

```bash
scp -i ~/.ssh/guinea_pigs.pem -r apache_2.4.49 ubuntu@15.160.68.117:~/apache
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "bash ~/apache/setup.sh"
```

### Switch to Apache 2.4.25 (Auth Bypass)

```bash
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose down"
scp -i ~/.ssh/guinea_pigs.pem -r apache_2.4.25 ubuntu@15.160.68.117:~/apache
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "cd ~/apache && sudo docker-compose build --no-cache && sudo docker-compose up -d"
```

---

## Check Status

```bash
# Check running container
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "sudo docker ps"

# Check logs
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "sudo docker logs vulnerable-apache-2.4.49"

# Test health endpoint
ssh -i ~/.ssh/guinea_pigs.pem ubuntu@15.160.68.117 "curl localhost:8080/health"
```

---

## EC2 Info

| Setting | Value |
|---------|-------|
| **IP** | 15.160.68.117 |
| **URL** | https://gpigs.devergolabs.com |
| **Port** | 8080 |
| **Health Check** | `/health` |
