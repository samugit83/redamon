# RedAmon single-host deploy

Provision and operate a full RedAmon instance on any Linux server (EC2, DigitalOcean,
Hetzner, bare metal) from your laptop, given only its **IP + an SSH credential + a domain**.

## What this is

`deploy.sh` is a thin remote driver around RedAmon's own `redamon.sh` control script. It
prepares a bare host, clones the repo onto it, drives `redamon.sh` over SSH, and wraps the
whole thing in an internet-facing security layer that `redamon.sh` deliberately does not
provide (RedAmon is designed local-only): nginx + TLS + firewall + host hardening.

**The security promise: one public origin over HTTPS.** From the internet only the webapp
UI (443, plus 80 for the ACME challenge and an HTTP->HTTPS redirect) is reachable. The agent
API, the outbound Kali MCP servers, databases, orchestrator, and the reverse-shell catcher
stay bound to loopback. nginx proxies the webapp and (same-origin) exactly the four agent
WebSocket paths; nothing else on the agent is exposed.

**One exception, off by default: the INBOUND MCP server.** With
`MCP_SERVER_ENABLED=true` the same origin also serves `/api/mcp-server`, a credentialed
machine-facing endpoint an external AI agent connects to with a bearer token. It is a
different shape of surface from the UI, so it has its own section below.

### Quick start

```bash
cd tooling/deploy/single-host
cp .env.example .env
# edit .env: HOST_IP, DOMAIN, SSH_KEY_PATH, OPERATOR_ALLOW_CIDRS, LETSENCRYPT_EMAIL,
#            ADMIN_NAME / ADMIN_EMAIL / ADMIN_PASSWORD
./deploy.sh init
```

First build takes **30-60 minutes** (Kali + agent images). When it finishes, log in at
`https://<your-domain>/` with the admin you set in `.env`.

> **Upgrading from before 6.9?** This directory moved from `deploy/single-host` to
> `tooling/deploy/single-host`. `git pull` moves only tracked files, so your `.env` and
> any provided TLS material stay at the old path. Run `./redamon.sh migrate-layout` from
> the repo root once to move them (`./redamon.sh update` and `up` do it automatically).
> Until then `deploy.sh` falls back to the old location and warns.

## Prerequisites

**Local machine:** `bash`, `ssh`, `scp`, `curl`. Only for password auth you also need
`sshpass` (`apt install sshpass` / `brew install hudochenkov/sshpass/sshpass`). Key auth is
recommended and needs nothing extra.

**The server:** a fresh Ubuntu 22.04/24.04 box. You install **nothing** on it by hand -
`deploy.sh` detects and installs every prerequisite (Docker Engine 28.0.0 or newer + Compose
v2, nginx, certbot, ufw, fail2ban, swap, ...) idempotently. See "How the host is bootstrapped"
below.

## Server sizing

RedAmon is heavy. `redamon.sh` enforces a hard **8 GB** Docker-visible RAM floor at bring-up
(effective ~7.5 GB after slack), aborting below it unless `REDAMON_SKIP_RAM_GATE=true`.

| Profile | vCPU | RAM | Disk | Example | Notes |
|---|---|---|---|---|---|
| Bare minimum (core only, no GVM/KB) | 2 | 8 GB | 100 GB | t3.large | Fits the ~91 GB platform footprint with almost no operational headroom. Cap the build cache (`DOCKER_BUILD_CACHE_MAX_GB`) or the parallel build can hit 100%. Slow/swappy; keep swap on. Supply-chain scans will be admission-rejected here (see below). |
| Recommended (core + real scans, no GVM) | 4 | 16 GB | 200 GB | m5.xlarge | ~91 GB platform + ~100 GB free for operational data. Sane default, and the floor for supply-chain SCA. |
| Full (GVM + KB + Ollama judge + parallel scans) | 8 | 32 GB | 250 GB | m5.2xlarge | ~121 GB platform + ~100 GB operational. Ollama alone needs ~5-6 GB RAM while scanning. |

**Disk sizing.** The fixed platform footprint is **~91 GB without GVM** (OS ~9 GB + the 15 built
images ~61 GB + build cache ~20 GB + the ~0.3 GB offline OSV database volume) and **~121 GB with
GVM** (its images plus the vulnerability-feed volumes/DB add ~25-30 GB, and those grow on every
feed update). On top of that, budget **~100 GB of free space for operational data** - the Neo4j
attack graph, scan artifacts/outputs, Postgres, and container logs all grow with use. That lands
at **200 GB without GVM, 250 GB with GVM**, each leaving roughly 100 GB free for operations. gp3
EBS resizes online, so you can start smaller and grow in place. `install` and `update` now drop the
cache each build orphans, which holds that ~20 GB line item near its floor instead of letting it
creep; `DOCKER_BUILD_CACHE_MAX_GB` remains the belt-and-suspenders daemon-level ceiling.

**RAM and supply-chain SCA.** Supply-chain is the only feature that spawns a *second* heavy
container per job: the scan/partial books a 1.75 GB envelope and the network-isolated "dirty"
analyzer another ~1.5 GB alongside it. The memory governor reserves both, so a starved host
*rejects the scan* rather than OOM-killing the stack - but on the 8 GB bare-minimum profile that
rejection is the normal outcome once anything else is running. Plan on the 16 GB profile if you
intend to use supply-chain SCA.

## The `.env` reference (every variable)

`cp .env.example .env`, then fill it in. Every key, grouped as in the file:

### Connection (CLI positionals override these)
| Key | Purpose | Local-only |
|---|---|---|
| `HOST_IP` | Public IP/DNS of the target. Required. | yes |
| `REMOTE_USER` | SSH sudoer (default `ubuntu`). | yes |
| `SSH_KEY_PATH` | Path to `.pem` key (recommended). `~` is expanded. | yes (never copied to host) |
| `SSH_PASSWORD` | Password-auth fallback. Needs local `sshpass`. Discouraged. | yes |
| `SSH_PORT` | SSH port (default 22). Also drives the host ufw SSH-allow rule and the fail2ban `[sshd]` jail, so set it to the port the host's sshd actually listens on. | no (shipped to host) |

### Repo
| Key | Purpose |
|---|---|
| `REPO_URL` | Public clone URL. No token needed. |
| `REPO_BRANCH` | Branch to deploy (default `master`). |
| `APP_DIR` | Checkout dir name. Keep stable - it fixes `COMPOSE_PROJECT_NAME`, which redamon.sh uses for DB-volume detection. Do not change between init and update. |
| `REDAMON_VERSION` | Optional version stamp baked into images. Blank -> redamon.sh default. |

### Access mode
| Key | Purpose |
|---|---|
| `ACCESS_MODE` | `https-domain` (default) \| `https-ip` \| `http-domain` \| `http-ip`. See "Access modes" below. |
| `DOMAIN` | Required for `*-domain` modes; ignored for `*-ip`. |
| `HTTP_PORT` / `HTTPS_PORT` | Ports nginx listens on (and ufw opens). Default 80/443. Keep `HTTP_PORT=80` if using Let's Encrypt (http-01 always validates on 80). Change only when fronted by another LB/proxy that presents 80/443 to clients. |

### TLS (https-* only)
| Key | Purpose |
|---|---|
| `TLS_MODE` | `letsencrypt` (domain only) \| `provided` \| `self-signed` (ip only). |
| `LETSENCRYPT_EMAIL` | Required for letsencrypt. |
| `LETSENCRYPT_STAGING` | `true` issues against LE staging (not browser-trusted) while testing, to avoid the 5-certs/week rate limit. |
| `SSL_CERT_LOCAL` / `SSL_KEY_LOCAL` | `provided` mode: local paths (relative to this dir) SCP'd to the host. Drop files in `cert/`. |
| `SSL_KEY_PASSWORD` | Passphrase if the provided key is encrypted. |
| `HSTS_ENABLE` | Emit HSTS on https (default true). Auto-absent for http-*. |

### Access control / hardening
| Key | Purpose |
|---|---|
| `OPERATOR_ALLOW_CIDRS` | Comma list. nginx allow-gate + ufw 443 source. Strongly recommended. |
| `SSH_ALLOW_CIDRS` | Comma list for ufw :22. Blank -> falls back to `OPERATOR_ALLOW_CIDRS`. |
| `GATE_MODE` | `ip_allowlist` (recommended) \| `basic_auth` \| `none`. |
| `BASIC_AUTH_USER` / `BASIC_AUTH_PASS` | Required for `basic_auth`. |
| `WS_REQUIRE_SESSION` | Default `true`. nginx `auth_request` requires a valid webapp session cookie before ANY `/ws/*` upgrade. Keep it on as defense-in-depth: all four agent WS paths now enforce a signed ws-ticket + a server-side same-origin check at the app layer (fail-closed when `AGENT_WS_TICKET_SECRET` is unset), and this cookie gate sits in front of that as a second layer. |
| `CSP_ENFORCE` | Default `false` (Content-Security-Policy-Report-Only). Set `true` to enforce the CSP after confirming the WebGL graph and xterm terminal still render. |
| `ENABLE_UFW` | Host firewall (default true). |
| `ENABLE_SSH_HARDENING` | Key-only + no-root login. Skips disabling password login if you deployed over a password (so you don't lock yourself out). |
| `ENABLE_FAIL2BAN` | sshd + nginx jails. |
| `ENABLE_UNATTENDED_UPGRADES` | Auto security patches. |

### Feature flags (map to redamon.sh)
| Key | Maps to | Notes |
|---|---|---|
| `ENABLE_GVM` | `--gvm` | Heavy; 10-20 min feed sync; the install generates a strong `GVM_PASSWORD` (pinned in the server `.env`) and applies it to gvmd's `admin`. |
| `ENABLE_KB` | `--kbase` | Bakes ML embedding models (+~4.4 GB image). The real KB switch. |
| `ENABLE_KB_REFRESH` | kb-refresh sidecar | |
| `ENABLE_ZRAM` | `REDAMON_ENABLE_ZRAM=1` | Compressed-RAM cushion. |

`SKIP_KB` is intentionally **not** an input: redamon.sh derives it from the `.kbase-enabled`
flag it manages. Control KB with `ENABLE_KB` only.

### Resources / tuning
| Key | Purpose |
|---|---|
| `SWAP_PCT` | Swapfile as a percentage of host RAM, at ANY size (default 25, `0` skips). 25% is what unlocks the memory governor's higher burst factor. |
| `SWAP_SIZE_GB` | DEPRECATED explicit override in GB; blank uses `SWAP_PCT`. |
| `OS_RESERVE_PCT` / `SERVICES_PCT` / `BURST_FACTOR` / `BURST_SWAP_MIN_PCT` / `BLAST_PCT` / `DISK_RESERVE_PCT` / `REDAMON_WEIGHT_*` | Memory-governor shares. Percentages only, so the same file is correct on an 8 GB and a 64 GB instance: redamon.sh computes the actual sizes from the target's own RAM. |
| `REDAMON_SKIP_RAM_GATE` | `true` bypasses the 8 GB floor on tiny boxes (risky). |
| `REDAMON_BUILD_PARALLEL` | Cap concurrent image builds. Blank -> redamon.sh auto-sizes. |
| `DOCKER_DNS` | e.g. `8.8.8.8,8.8.4.4` merged into `/etc/docker/daemon.json` if container DNS breaks. |
| `DOCKER_BUILD_CACHE_MAX_GB` | Cap the BuildKit build cache (GB) via `daemon.json` auto-GC. Blank -> Docker's default. `install`/`update` already drop the cache each build orphans, so this is a second-line ceiling for cache the daemon accumulates outside RedAmon's builds; set e.g. `30` on a shared or long-lived host. |
| `<SERVICE>_CPUS` | Per-service CPU limit (`NEO4J_CPUS`, `KALI_CPUS`, `AGENT_CPUS`, ...). Auto-capped at `init` to `min(compose default, host nproc)` so `up` never fails on a box with fewer CPUs than compose's generous defaults (neo4j 8 / kali 10 / agent 8). Set one to pin it; blank -> auto. |

### Engagement knobs
| Key | Purpose |
|---|---|
| `REVSHELL_TARGET_CIDRS` | Scopes the ufw 4444 rule to your RoE targets. 4444 is loopback-bound by default; see the Security posture section for how to actually catch reverse shells (tunnel, or republish + DOCKER-USER rule). |
| `TUNNELS_ENABLED` | Keep `false` on an internet-exposed host. |

### First admin (required for init)
| Key | Purpose |
|---|---|
| `ADMIN_NAME` / `ADMIN_EMAIL` / `ADMIN_PASSWORD` | The first admin user, created automatically during `init`. There is **no** app-layer login lockout, so use a strong password (nginx `limit_req` is the only brute-force brake). |

### Optional app config (appended to the server .env)
| Key | Purpose |
|---|---|
| `NVD_API_KEY` | Faster NVD lookups. |
| `KB_EMBEDDING_USE_API` / `KB_EMBEDDING_API_BASE_URL` / `KB_EMBEDDING_API_KEY` | Use a remote embedding API instead of the baked local model. |
| `OSV_DB_AUTO_REFRESH` | `false` disables the lazy-on-scan refresh of the offline OSV database. Set it for an **air-gapped** host, otherwise every supply-chain scan burns `OSV_DB_REFRESH_TIMEOUT` on a download that cannot succeed. Blank -> `true`. |
| `OSV_DB_ECOSYSTEMS` | Comma-separated ecosystems to keep synced. Blank -> all eight (~280 MB). `npm` alone is ~208 MB and a noticeably shorter first install. An ecosystem you drop here is never refreshed, and a scan against it reports a missing ecosystem rather than a clean result. |
| `OSV_DB_TTL_SECONDS` | Freshness window before a re-sync (blank -> 86400). |
| `OSV_DB_REFRESH_TIMEOUT` | Ceiling on a single refresh, seconds (blank -> 900). |
| `SCA_INTEL_AUTO_REFRESH` | `false` stops contacting the supply-chain **incident catalog** feed (supplychainattack.org, ~5 MB) on an **air-gapped** host; an empty catalog still receives the bundled offline copy, installed with no network. Blank -> `true`. Unlike the OSV database this one is also seeded at install/update, because captured traffic is matched against it without any scan having run. |
| `SCA_INTEL_TTL_SECONDS` | Freshness window before a re-sync (blank -> 86400). |
| `SCA_INTEL_RETRY_SECONDS` | Retry floor after a failed or rejected fetch (blank -> 3600), so a broken feed is not re-fetched on every scan. |
| `SCA_INTEL_REFRESH_TIMEOUT` | Ceiling on a single refresh, seconds (blank -> 120). Lower than the OSV one because this feed is ~5 MB, not ~208 MB. |
| `SCA_INTEL_BOOTSTRAP_ON_SCAN` | `false` stops a scan populating a cold catalog volume (blank -> `true`). |
| `SCA_INTEL_MATCH_ENABLED` | `false` turns off matching captured requests against the catalog (blank -> `true`). |
| `CAPTURE_IOC_IGNORE_SUFFIXES` | Hosts excluded from that match. Blank -> the five OAST providers the catalog lists as indicators, so your own Burp Collaborator callbacks are not flagged. |
| `API_USAGE_CHECK_ENABLED` | `false` (or `0`, `no`, `off`, any case) turns off **Settings > API Keys > Check API usage** on an **air-gapped** host: the check makes the webapp call each provider's account/usage endpoint with the saved keys, on demand. The last saved report stays readable. Blank -> `true`. |
| `WORKSPACE_URL_IMPORT_ENABLED` | `false` turns off **Import from URL** in the Agent Workspace for every user (folder and archive uploads stay). Blank -> on. See below. |

LLM provider keys are configured in the UI, not here.

**Supply-chain SCA / offline OSV database.** `init` and `update` call `redamon.sh`'s
`ensure_osv_db`, which populates the `redamon-osv-db` volume (~280 MB for all eight ecosystems)
after the tool images are built. It is **best-effort**: a network failure warns and lets the
stack come up, so `verify` re-checks the volume and warns if it is empty. To fix one by hand:
`ssh` in and run `./redamon.sh supply-chain-sync` (optionally `... npm PyPI Go`). The download
is plain HTTPS egress to the OSV GCS bucket, which the default ufw policy (`allow outgoing`)
already permits.

**Agent Workspace URL import.** A signed-in user can import a repository, an archive, a file
or a copy of a website into the Agent Workspace, so this server fetches public URLs that users
name: plain HTTP(S) egress, which `allow outgoing` permits. Private, loopback and metadata
addresses are refused on the link and on every redirect, and a website copy keeps to the
project's Rules of Engagement. It is on by default; `WORKSPACE_URL_IMPORT_ENABLED=false` turns
it off; a change reaches the running agent on the next `deploy.sh update`, because
`redamon.sh update` brings the running services onto the changed `.env` even when there is no
new code (only a service whose configuration changed is recreated).

### Behaviour / safety
| Key | Purpose |
|---|---|
| `INIT_FORCE` | `true` skips the typed `INIT` wipe confirmation (CI only - dangerous). |
| `BACKUP_BEFORE_UPDATE` | Reserved (pre-update DB snapshot). |
| `DRY_RUN` | Print the resolved plan and exit without touching the host. |
| `VERBOSE` | Stream full remote output. |
| `ALLOW_INSECURE` | Must be `1` to permit http-* modes. |

## Access modes

| Pick | When |
|---|---|
| `https-domain` | You have a real DNS name pointing at the host. The default and recommended. Use `TLS_MODE=letsencrypt`. |
| `https-ip` | Bare IP, no DNS, but you still want TLS. `TLS_MODE=self-signed` (browser warning) or `provided`. |
| `http-domain` / `http-ip` | Lab/test only. No TLS. Gated behind `ALLOW_INSECURE=1` and a loud banner - they invert the whole security posture (plaintext cookies/creds, no HSTS, agent WS unencrypted). |

Derived automatically from `ACCESS_MODE` (you never set these):

| ACCESS_MODE | Public host | nginx | WS scheme | Secure cookie / HSTS |
|---|---|---|---|---|
| `https-domain` | `$DOMAIN` | 443 + 80->443 | `wss://$DOMAIN/ws/...` | on |
| `https-ip` | `$HOST_IP` | 443 + 80->443 | `wss://$HOST_IP/ws/...` | on (self-signed warning) |
| `http-domain` | `$DOMAIN` | 80 only | `ws://$DOMAIN/ws/...` | off |
| `http-ip` | `$HOST_IP` | 80 only | `ws://$HOST_IP/ws/...` | off |

The agent WebSocket URL is **baked into the webapp image at build time**
(`NEXT_PUBLIC_AGENT_WS_URL`). Changing the scheme or host later requires a webapp rebuild
(re-run `update`), not just an nginx reload.

## TLS setup

- **letsencrypt** (recommended, `https-domain`): needs `DOMAIN` resolving to the host and
  port 80 reachable. The deploy stands up an ACME webroot on 80, runs `certbot certonly
  --webroot`, then installs the hardened 443 vhost pointing at
  `/etc/letsencrypt/live/$DOMAIN/`. Auto-renew is wired via certbot's timer + an nginx reload
  hook. Set `LETSENCRYPT_STAGING=true` while testing.
- **provided** (`https-domain` or `https-ip`): drop `fullchain.pem` + `privkey.pem` in
  `cert/` (or point `SSL_CERT_LOCAL`/`SSL_KEY_LOCAL` at them). They are SCP'd to
  `/etc/ssl/redamon/` (key `600`), md5-idempotent. The only way to a trusted cert on a bare IP.
- **self-signed** (`https-ip` escape hatch): generated on the host with the IP in a SAN.
  Browser warning expected. Not for production.
- **No TLS** (`http-*`): certbot is skipped entirely.

## Commands

| Command | What it does | Destructive |
|---|---|---|
| `./deploy.sh init` | Wipe ALL Docker state + the checkout, then build from zero. Auto-creates the first admin from `.env`. | **yes** (typed `INIT` confirm) |
| `./deploy.sh update` | Pull latest `REPO_BRANCH` HEAD and apply (diff-driven rebuild via redamon.sh). Preserves all volumes/data. | no |
| `./deploy.sh status` | redamon.sh status + `docker compose ps` + ufw + nginx -t + cert expiry. | no |
| `./deploy.sh harden` | Re-apply host hardening + nginx/TLS only (idempotent), no rebuild. | no |
| `./deploy.sh ssl-renew` | Renew (certbot) or re-install (provided) the cert + reload nginx. | no |
| `./deploy.sh down` | Stop the stack, keep volumes/images. | no |
| `./deploy.sh logs [service]` | Tail `docker compose logs -f` for a service (default `agent`). | no |
| `./deploy.sh revshell-open` | Per-engagement: expose `4444` to `REVSHELL_TARGET_CIDRS` via a host socat forwarder (fails closed on reboot). | no |
| `./deploy.sh revshell-close` | Tear the `4444` forwarder down and remove its ufw rules. | no |

Connection fields can be overridden positionally, e.g.
`./deploy.sh init 1.2.3.4 ~/.ssh/redamon.pem ubuntu`. Use `--env NAME` to select
`.env.NAME` for per-instance configs (`prod`, `staging`, a client name).

## The inbound MCP server (off by default)

`MCP_SERVER_ENABLED=true` exposes `/api/mcp-server` so your own AI agent can start recon
scans, read the attack-surface graph and adjust recon tuning, acting as ONE RedAmon user
inside that user's own projects. Tokens are minted per user in Global Settings ->
**MCP Server**; the full model is in
[docs/readmes/README.MCP.SERVER.md](../../../docs/readmes/README.MCP.SERVER.md).

**Three gates sit in front of it, and all three must admit the agent.** This is the part
that surprises people, because two of them are invisible from the app:

| Layer | Controlled by | If it refuses |
| --- | --- | --- |
| Cloud Security Group | your provider | connection times out |
| ufw on the app port | `OPERATOR_ALLOW_CIDRS` + `MCP_CLIENT_CIDRS` | connection refused/dropped, **nginx never sees it** |
| nginx `location = /api/mcp-server` | `MCP_CLIENT_CIDRS`, `MCP_EDGE_ALLOW_BEARER` | 403 |

The firewall filters by PORT and cannot see the URL path. So when
`OPERATOR_ALLOW_CIDRS` is set (the recommended posture), an agent connecting from anywhere
else is dropped **before** nginx, and `MCP_EDGE_ALLOW_BEARER=true` on its own changes
nothing. Set `MCP_CLIENT_CIDRS` to your agent's egress range: it is admitted to the port,
then narrowed by the nginx location to `/api/mcp-server` only. It does not gain the UI, the
login page, or the agent WebSocket paths.

Two hard rules the deploy enforces for you:

- **`http-*` modes are refused outright.** The credential is a bearer token in a header;
  over plaintext it is broadcast on every call and, unlike a session cookie, it outlives
  the session. `ALLOW_INSECURE=1` does not override this.
- **`GATE_MODE=basic_auth` returns 403** until `MCP_EDGE_ALLOW_BEARER=true`, because Basic
  and Bearer cannot share one `Authorization` header.

`deploy.sh verify` probes the endpoint and distinguishes the failure modes: 404 (disabled or
the flag never reached the container), 401 (working), 403 (the edge gate ate the header).
Repeated 401s are banned by the `redamon-mcp-auth` fail2ban jail.

In `https-ip` with a self-signed certificate most MCP clients reject the connection. Use a
real certificate (`TLS_MODE=provided`) or a domain.

### Agent in the Loop (on, once the MCP server is)

`AGENT_IN_THE_LOOP_ENABLED` (default `true`) lets a person pick **Agent in the Loop** as a
chat's model: their own Claude Code or Codex then answers each reasoning step of that run
through the `loop_*` MCP tools. It needs the MCP server, which stays off by default on a
deploy: until you set `MCP_SERVER_ENABLED=true`, `deploy.sh` notes that the switch is
inert. `deploy.sh` also writes `REDAMON_SINGLE_HOST_DEPLOY=true` into the server's app `.env`, so
`redamon.sh` (which turns the MCP server on by default on a local install) never turns it on
here, even when someone runs `./redamon.sh update` on the server by hand; `verify` reports an
MCP server that answers while configured off as an error. Against an app older than Agent in
the Loop, `verify` skips the loop check. The flag is seeded into the server `.env` and passed to
both the `agent` and `webapp` containers; `deploy.sh verify` checks that it reached both.
The three gates above apply unchanged (the driver is just another MCP client), and
`MCP_RATE_LOOP_PER_MIN` (default 120) is the per-token rate of the loop tools. The client
setup is on the wiki page
[Agent in the Loop](https://github.com/samugit83/redamon/wiki/Agent-in-the-Loop).

## The plugin platform

Every deploy runs the RedAmon plugin platform: the Plugins page, where an admin installs
optional features from the signed `redamon-plugins` catalog, and the `plugin-runner` and
`plugin-gateway` containers that run them on an internal network with no internet access.
There is nothing to turn on. `deploy.sh init` and `update` set `PLUGINS_ALLOWED_ORIGIN` in the
server `.env` from the same derived origin as `MCP_ALLOWED_ORIGIN` (nginx forwards
`Host $host` without the port), and the update's explicit webapp recreate passes
`-f docker-compose.plugins.yml` so the webapp keeps its plugin network and volume.

- **Docker Engine 28.0.0 or newer is required on the server.** The plugin networks use
  `gateway_mode_ipv4: isolated`, which older engines refuse, and `redamon.sh` stops on an
  older engine before building anything. `init`, `harden` and `update` (before its pull)
  install Docker from Docker's apt repo when the engine is older than 28.0.0 and fail if it
  is still older afterwards, so `./deploy.sh update` brings an existing server's Docker up to
  date by itself. Check with `docker version --format '{{.Server.Version}}'`.
- **A server that cannot run the platform is refused.** `redamon.sh` generates
  `PLUGIN_RUNNER_KEY` and `PLUGIN_CALL_TOKEN_SECRET`, then a preflight checks them, the
  internal key, the engine, the runner image and the plugin networks before any service is
  (re)created; a failure stops the deploy with `The plugin platform cannot run on this host:
  <reason>.`, and `./redamon.sh status` repeats the reason.
- **The secrets gate covers both plugin secrets**: an unset, known-default or shorter than 24
  characters `PLUGIN_RUNNER_KEY` or `PLUGIN_CALL_TOKEN_SECRET` fails the deploy.
- **The plugin-internal routes are denied at nginx** in both templates, before
  `location /api/`: `/api/plugin-gateway/` (plugin code's Gateway), `/api/plugin-runner/`
  (the runner's run list) and `/api/internal/plugins/` (reconciliation) answer 404 at the
  edge. They are reached only on the container networks; nginx does not strip the headers
  they authenticate with, so the edge must not offer them.
- The runner's CPU cap (`PLUGIN_RUNNER_CPUS`, 2) is fitted to the server's cores like the
  other services' caps.
- **Installing from the official catalog needs outbound HTTPS** from the server to
  `raw.githubusercontent.com` (the signed catalog), `github.com` and
  `release-assets.githubusercontent.com` (the release archives); `PLUGINS_DOWNLOAD_HOSTS` is the
  allowlist checked on every redirect hop. Without egress, an admin can still install a plugin
  from files on the Plugins page.

## Security posture

RedAmon's threat model assumes a local-only deployment with no anonymous internet attacker.
Putting it on a public IP invalidates that, so the deploy closes the gap:

- Parts of the agent REST API remain **unauthenticated** (`/sessions/*`, `/files`, FastAPI
  `/docs` + `/openapi.json`; the `/workspace/*` family needs the internal key); `/graph/exec` and
  `/emergency-stop-all` now require `require_internal_auth` (wave 2). All four WS paths now
  enforce a signed ws-ticket + a server-side same-origin check and **fail closed** when
  `AGENT_WS_TICKET_SECRET` is unset - including `/ws/kali-terminal` (the root PTY) and the two
  cypherfix sockets that clone repos / edit code. The deploy still treats the agent as fully
  untrusted from the edge:
  - nginx proxies **only** the four `/ws/*` paths to the agent - never any agent REST route.
  - **`auth_request` (WS_REQUIRE_SESSION=true)** makes nginx validate the webapp session
    cookie against `/api/auth/me` before allowing any WS upgrade, so reaching those
    agent sockets requires a logged-in user - not just a network position - on top of the
    app-layer ws-ticket.
  - the operator **IP allowlist / basic-auth gate** sits in front of everything.
- The webapp trusts `X-Internal-Key` as a service-to-service **auth bypass** and injects
  `X-User-Id` / `X-User-Role` downstream after auth. nginx **strips these inbound headers** on
  every request (plus `X-Powered-By`) so a client can never spoof identity or bypass auth.
- There is **no login rate-limit or lockout** in the app. nginx supplies `limit_req` on
  `/api/auth/login` (5r/m) and a general `/api/` limit (30r/s), a per-IP connection cap, and
  slowloris timeouts.
- **Headers:** the webapp sets none of its own, so nginx is authoritative - HSTS, a tightened
  CSP (no `unsafe-eval`; `object-src 'none'`; `base-uri`/`form-action 'self'`), `X-Frame-Options
  DENY`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`, and COOP/CORP.
- **TLS:** TLS 1.2/1.3 only, modern ECDHE ciphers, `ssl_session_tickets off`, OCSP stapling.
- Every secret must be strong: the deploy runs a **secrets gate** that fails the build on any
  unset/default/short secret (`changeme`, `redamon_secret`, ...). redamon.sh generates them;
  the deploy only verifies.
- `ip_allowlist` (default `GATE_MODE`) is strongly recommended given the powerful
  agent WS surface + root PTY - defense-in-depth on top of the app-layer ws-ticket and login.
- **Reverse shell (4444)** is bound to loopback by the prod overlay and closed at the
  firewall. To catch a *direct* reverse shell during an engagement, set
  `REVSHELL_TARGET_CIDRS` to your RoE target scope and run `./deploy.sh revshell-open`; run
  `./deploy.sh revshell-close` the moment you are done. How it works: `revshell-open` starts a
  transient `socat` forwarder on the host's public IP (`<public-ip>:4444 -> 127.0.0.1:4444`)
  and opens `4444` in ufw to your target CIDRs only. Because `socat` is a **host** listener
  (not a Docker-published port), ufw's source scoping actually applies - a plain ufw rule on
  a Docker-published port would be bypassed by Docker's own iptables chains. A host **reboot
  drops the forwarder**, so 4444 fails closed. The msf handler on 4444 is unauthenticated, so
  it is exposed only to `REVSHELL_TARGET_CIDRS`, never the world; set your payload's LHOST to
  the host's public IP and start the msf handler in RedAmon. (Alternative: a tunnel
  ngrok/chisel to `127.0.0.1:4444` with `TUNNELS_ENABLED=true`; never run a world-open 4444
  and a tunnel at once.)
- If `ENABLE_GVM=true`, the install generates a strong `GVM_PASSWORD`, pins it in the server
  `.env`, and applies it to gvmd's `admin` user (so the app and gvmd never disagree). The
  deploy prints `admin / <password>` once; it is always recoverable with
  `grep '^GVM_PASSWORD=' ~/redamon/.env` on the host.

### Cloud firewall / Security Group

`deploy.sh` configures the host `ufw`, but on a cloud host your **provider firewall (AWS
Security Group / GCP firewall / Azure NSG) is the reliable outer boundary** — Docker's own
iptables chains can bypass `ufw`, so the cloud firewall is what still protects you if a
loopback re-bind is ever wrong (e.g. a stray `docker compose up` that republishes
`3000`/`8090`/`4444` on `0.0.0.0`). Open **only**:

| Port | Source | Purpose |
|---|---|---|
| **443/tcp** | your `OPERATOR_ALLOW_CIDRS` (or `0.0.0.0/0` if you rely on the nginx gate) | the app (HTTPS) |
| **80/tcp** | `0.0.0.0/0` | Let's Encrypt ACME challenge + redirect to 443 (required for `TLS_MODE=letsencrypt`) |
| **22/tcp** | your IP only | SSH management |

**Open nothing else.** In particular do **not** open `8090` (agent), `3000` (webapp),
`5432`/`7687`/`7474` (PostgreSQL/Neo4j), or `8000-8016`/`4444`/`8015` (Kali MCP / progress /
tunnel manager / PTY / reverse-shell) — all are loopback-bound and reached only through nginx
on `443`. Opening `8090` would expose the agent's unauthenticated WebSockets (including the
anonymous **root PTY** `/ws/kali-terminal`) and its REST surface directly, bypassing nginx and
its session gate. The browser reaches the agent's WebSockets at `wss://<domain>/ws/…` on `443`
(nginx → `127.0.0.1:8090`), so `8090` never needs to be publicly reachable.

> **nginx runs on the host, not in a container.** It sits **only at the edge** (80/443),
> reverse-proxying to two loopback backends — the **webapp** (`127.0.0.1:3000`, for `/` and
> `/api/*`) and the **agent** (`127.0.0.1:8090`, for the four `/ws/*` paths only). It is **not**
> a middlebox between containers: all internal service-to-service traffic (webapp ↔ agent ↔
> orchestrator ↔ DBs ↔ Kali) flows directly over the Docker bridge networks and never passes
> through nginx.

## First-run walkthrough

1. `cp .env.example .env`; set `HOST_IP`, `DOMAIN`, `SSH_KEY_PATH`, `OPERATOR_ALLOW_CIDRS`,
   `LETSENCRYPT_EMAIL`, and `ADMIN_NAME`/`ADMIN_EMAIL`/`ADMIN_PASSWORD`. Point `DOMAIN`'s
   A-record at `HOST_IP` first (letsencrypt needs it).
2. `./deploy.sh init` -> type `INIT` to confirm the wipe.
3. Watch: teardown -> host bootstrap -> hardening -> clone + overlay -> `redamon.sh install`
   (30-60 min build) -> secrets gate -> admin bootstrap -> nginx + TLS -> verify.
4. Verification asserts loopback binds (3000/8090 on 127.0.0.1 only), datastores never
   off-loopback, container health, an admin exists, and `https://<domain>/api/health` -> 200.
5. Log in at `https://<domain>/`.

`DRY_RUN=true ./deploy.sh init` prints the resolved plan without touching the host.

## How the host is bootstrapped

`init` (and `harden`) run a dynamic detect-and-install matrix (`update` runs its Docker
Engine + Compose step only, before the pull) - each item is probed and
installed only if missing or too old, idempotently: base apt packages (git, openssl, curl,
jq, expect, ...), **Docker Engine 28.0.0 or newer + Compose v2.24 or newer from Docker's
official repo** (purging any old `docker.io`/v1 compose first; an older engine or Compose is
upgraded, and the bootstrap fails if either is still too old afterwards), the docker service + group membership, nginx, certbot (only
when letsencrypt is used), ufw, fail2ban, unattended-upgrades, a swapfile sized at `SWAP_PCT` of RAM
hosts, optional Docker DNS, and inotify limits. Nothing is assumed pre-present.

## Update and rollback

`update` first upgrades Docker Engine and Compose when they are too old (a no-op on a current
host), then wraps `redamon.sh update`: `git pull --ff-only` + diff-driven
selective rebuild + secret regen (all via redamon.sh, which preserves DB passwords by volume
detection), then re-renders nginx. The settings it seeds take effect in the same run, even
with no new code: `redamon.sh update` brings every running service onto the current `.env`,
recreating only the ones whose configuration changed. No source patches are applied: the single-origin agent WS
URL is a first-class `ARG NEXT_PUBLIC_AGENT_WS_URL` in the base `webapp/Dockerfile`, baked from
the prod overlay's build-arg, so redamon.sh's own webapp rebuild bakes the right value.
**All engagement data (Postgres, Neo4j, reports, GVM feeds, models) lives in named volumes
that survive `update`.**

The prod compose overlay (`compose/docker-compose.prod.yml`) is SCP'd to the host and installed
at `$HOME/.redamon-deploy` (outside the checkout, so it never blocks `git pull --ff-only`). It
sets `NEXT_PUBLIC_AGENT_WS_URL=wss://<host>/ws/agent` as the webapp build-arg. The deploy works
even if `tooling/deploy/single-host/` is not committed to the cloned branch (committing it is still fine
and makes the overlay part of the repo history).

Rollback is manual: `git reset --hard <prev>` on the host checkout, then `./deploy.sh update`.

## Troubleshooting and FAQ

- **RAM gate abort** ("need ~8 GB"): provision more RAM, or set `REDAMON_SKIP_RAM_GATE=true`
  (risky) and keep swap on (`SWAP_PCT`).
- **certbot fails**: `DOMAIN` must resolve to the host and port 80 must be reachable (open it
  in your cloud Security Group / `OPERATOR_ALLOW_CIDRS` must not block the ACME check - LE
  validates from arbitrary IPs, so 80 must be world-open). Use `LETSENCRYPT_STAGING=true` to
  iterate without burning the rate limit.
- **Secrets-gate failure**: a secret is unset/default/short. redamon.sh should have generated
  them; check the server `~/<APP_DIR>/.env`.
- **GVM feed-sync wait**: with `ENABLE_GVM=true`, scans don't work until feeds finish syncing
  (10-20 min after first boot).
- **Never run raw `docker compose up` on the host.** The loopback re-binds hold only while
  the prod overlay is active (`COMPOSE_FILE`). A bare `docker compose up` reloads the base
  file and republishes 3000/8090/4444 on 0.0.0.0 and starts the profile-less GVM stack.
  Always go through `redamon.sh` (which the deploy points at the overlay). `redamon.sh up dev`
  is likewise forbidden here (it hardcodes its own compose files and defeats the overlay).
- **Locked out over SSH**: if you deployed over a password, `ENABLE_SSH_HARDENING` will not
  disable password login. Install a key, then re-run `harden` with key auth to close it.

## The redamon.sh parameter surface

`deploy.sh` never edits `redamon.sh`. It drives it through four channels: the subcommand
(`MODE`), CLI flags on `install`, exported env vars, and keys appended to the server-side
application `.env`.

| `.env` key | Drives |
|---|---|
| `ENABLE_GVM` | `install --gvm` |
| `ENABLE_KB` | `install --kbase` |
| `ENABLE_ZRAM` | `REDAMON_ENABLE_ZRAM=1` |
| `REDAMON_BUILD_PARALLEL` | `REDAMON_BUILD_PARALLEL` (blank -> auto) |
| `DOCKER_BUILD_CACHE_MAX_GB` | `builder.gc.defaultKeepStorage` in `/etc/docker/daemon.json` (blank -> Docker default) |
| `REDAMON_SKIP_RAM_GATE` | `REDAMON_SKIP_RAM_GATE=1` |
| `REDAMON_VERSION` | image build-arg stamp |
| (fixed) | `COMPOSE_FILE` = base + prod overlay, made sticky |
| `APP_DIR` | `COMPOSE_PROJECT_NAME` (do not change between init/update) |
| `ADMIN_*` | first-admin creation on init |
| `NVD_API_KEY`, `KB_EMBEDDING_*`, `TUNNELS_ENABLED`, `OSV_DB_*` | appended to the server `.env` |

Intentionally hands-off (redamon.sh owns these; the deploy only verifies): `AUTH_SECRET`,
`INTERNAL_API_KEY`, `SCANNER_API_KEY`, `ORCHESTRATOR_API_KEY`, `MCP_AUTH_TOKEN`,
`AGENT_WS_TICKET_SECRET`, `TUNNEL_AUTH_TOKEN`, `POSTGRES_PASSWORD`, `NEO4J_PASSWORD`, and
`SKIP_KB` (derived from the `.kbase-enabled` flag).
