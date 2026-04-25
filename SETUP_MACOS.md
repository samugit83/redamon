# RedAmon — macOS Installation & Verification Guide

This document covers the end-to-end steps used to install and verify RedAmon on macOS,
complementing the upstream [README.md](README.md).

---

## Prerequisites

### 1. Install Docker Desktop

Docker Desktop bundles both the `docker` CLI and the `docker compose` v2 plugin.

```bash
brew install --cask docker
```

After installation, open Docker Desktop from Applications and wait for it to fully start
(the whale icon in the menu bar stops animating). Verify both tools are available:

```bash
docker --version
docker compose version
```

> **Note:** Docker Desktop must be running before you execute any `redamon.sh` commands.
> To start it from the terminal: `open /Applications/Docker.app`

---

## Installation

### 2. Clone the repository

```bash
git clone https://github.com/samugit83/redamon.git
cd redamon
```

### 3. Run the install script

```bash
# Core stack only (recommended for first-time setup):
./redamon.sh install

# Full stack with GVM/OpenVAS (~30 min, requires 8 GB RAM):
./redamon.sh install --gvm
```

The script will:
- Build all Docker images
- Start all core services
- Prompt you to create an admin account (see below)
- Ingest the Knowledge Base (FAISS + Neo4j)

### 4. Create the admin account

At the end of installation you will be prompted interactively:

```
[WARN] No admin user found. Let's create one.

  Admin name: <your display name>
  Admin email: <your email>
  Admin password: ********
  Confirm password: ********
```

> **Important — macOS TTY quirk:** If you run the install through a terminal multiplexer or
> non-interactive shell (e.g. a CI pipeline or agent-driven session), the interactive prompts
> may inject a `\u0001` control character at the start of your input. This corrupts the stored
> email and password, causing login to fail.
>
> **Fix:** If you cannot log in after install, run the following to inspect and repair the record:
>
> ```bash
> # Check stored email
> docker exec redamon-webapp node -e "
> const { PrismaClient } = require('@prisma/client');
> const p = new PrismaClient();
> p.user.findMany({ select: { name: true, email: true, role: true } })
>   .then(u => { console.log(JSON.stringify(u, null, 2)); p.\$disconnect(); });
> "
>
> # Fix corrupted name/email (replace values as needed)
> docker exec redamon-webapp node -e "
> const { PrismaClient } = require('@prisma/client');
> const p = new PrismaClient();
> p.user.updateMany({
>   where: { email: { contains: 'your@email.com' } },
>   data: { name: 'YourName', email: 'your@email.com' }
> }).then(r => { console.log('Updated:', r); p.\$disconnect(); });
> "
>
> # Reset password directly (bypasses TTY issues)
> docker exec redamon-webapp node -e "
> const { PrismaClient } = require('@prisma/client');
> const bcrypt = require('bcryptjs');
> const p = new PrismaClient();
> bcrypt.hash('yournewpassword', 10).then(hash =>
>   p.user.update({ where: { email: 'your@email.com' }, data: { password: hash } })
> ).then(u => { console.log('Password reset for:', u.email); p.\$disconnect(); });
> "
> ```

---

## Verification

### 5. Check service health

```bash
./redamon.sh status
```

All six core containers should be `Up (healthy)`:

| Container | Port(s) |
|---|---|
| `redamon-webapp` | 3000 |
| `redamon-agent` | 8090 |
| `redamon-kali` | 4040, 4444, 8000–8005, 8013–8015 |
| `redamon-recon-orchestrator` | 8010 |
| `redamon-neo4j` | 7474, 7687 |
| `redamon-postgres` | 5432 |

Or via Docker directly:

```bash
docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
```

### 6. Verify HTTP endpoints

```bash
# Should return 200
curl -o /dev/null -w "%{http_code}\n" http://localhost:3000/api/health

# Should redirect (307) to /login
curl -o /dev/null -w "%{http_code}\n" http://localhost:3000/
```

### 7. Smoke-test the login API

```bash
curl -s -c /tmp/rc.txt -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}'
```

A successful response returns the user object:

```json
{"id":"...","name":"YourName","email":"your@email.com","role":"admin"}
```

### 8. Smoke-test authenticated endpoints

```bash
# Login first (stores cookie in /tmp/rc.txt)
curl -s -c /tmp/rc.txt -b /tmp/rc.txt -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"your@email.com","password":"yourpassword"}' > /dev/null

# Projects list (empty on fresh install)
curl -s -b /tmp/rc.txt http://localhost:3000/api/projects

# Users list (admin only)
curl -s -b /tmp/rc.txt http://localhost:3000/api/users
```

---

## Post-install Configuration

Open **http://localhost:3000/settings** to configure:

- **LLM Providers** — OpenAI, Anthropic, OpenRouter, AWS Bedrock, Ollama, etc.
- **API Keys** — Tavily, Shodan, SerpAPI, NVD, Vulners, URLScan, and threat-intel keys
- **Tunneling** — ngrok or chisel for reverse shell tunneling

See the upstream [README.md](README.md) and the [project Wiki](https://github.com/samugit83/redamon/wiki) for full details.

---

## Useful Management Commands

| Command | Description |
|---|---|
| `./redamon.sh up` | Start all services |
| `./redamon.sh down` | Stop all services (data preserved) |
| `./redamon.sh status` | Show running services and version |
| `./redamon.sh update` | Pull latest code and smart-rebuild |
| `./redamon.sh reset-password` | Reset a user's password interactively |
| `./redamon.sh purge` | Remove everything including volumes |

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `docker: command not found` | Docker Desktop not installed | `brew install --cask docker` |
| `docker compose version` fails | Docker Desktop not running | `open /Applications/Docker.app` |
| Login returns "Invalid credentials" | Corrupted admin record (TTY quirk) | See fix in step 4 above |
| Container stuck in "starting" | Insufficient RAM | Ensure ≥4 GB free RAM in Docker Desktop settings |
| Port already in use | Another service on 3000/5432/7687 | `lsof -i :<port>` then stop the conflicting process |

For more, see [readmes/TROUBLESHOOTING.md](readmes/TROUBLESHOOTING.md) or the [Wiki Troubleshooting page](https://github.com/samugit83/redamon/wiki/Troubleshooting).
