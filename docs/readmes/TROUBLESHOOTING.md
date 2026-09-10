# Troubleshooting

> **Full troubleshooting guide**: [Wiki — Troubleshooting](https://github.com/samugit83/redamon/wiki/Troubleshooting)

## Operating System Compatibility

RedAmon is fully Dockerized and runs on **any OS** that supports Docker and Docker Compose v2+. Below are common OS-specific issues and their fixes.

### Linux

| Problem | Cause | Fix |
|---------|-------|-----|
| Docker socket permission denied | User not in `docker` group | `sudo usermod -aG docker $USER` then log out and back in |
| `docker compose` not found | Old Docker version uses `docker-compose` (hyphen) | Install [Docker Compose V2 plugin](https://docs.docker.com/compose/install/) or use `docker-compose` |
| Port already in use (3000, 8010, etc.) | Another service occupies the port | Change ports in `.env` or stop the conflicting service |
| Containers killed (OOM) | Insufficient RAM | Increase swap or free memory — see [minimum requirements](../../README.md#prerequisites) |
| Volume mount denied (SELinux) | Fedora / RHEL / CentOS enforce SELinux | Add `:z` suffix to volume mounts in `docker-compose.yml`, or run `sudo setsebool -P container_manage_cgroup on` |
| Firewall blocks container traffic | `firewalld` or `ufw` blocking Docker bridge | `sudo ufw allow in on docker0` or allow the Docker subnet in firewalld |
| DNS fails inside containers | `systemd-resolved` conflicts (Ubuntu 22.04+) | Add `{"dns": ["8.8.8.8", "8.8.4.4"]}` to `/etc/docker/daemon.json` and restart Docker |
| `/var/run/docker.sock` not found | Docker not running or rootless Docker uses a different path | `sudo systemctl start docker` or set `DOCKER_HOST` to the correct socket path |

### Windows

| Problem | Cause | Fix |
|---------|-------|-----|
| Docker socket unavailable | Windows uses named pipes, not Unix sockets | Use [Docker Desktop](https://www.docker.com/products/docker-desktop/) with **WSL2 backend** enabled |
| Line ending errors (`\r\n`) | Git auto-converts LF → CRLF on Windows | `git config --global core.autocrlf input` then re-clone the repo |
| Path too long errors | Windows 260-character path limit | `git config --global core.longpaths true` |
| Volume mount fails | Windows path format incompatible with Linux containers | Run from inside WSL2 filesystem (`~/redamon`), **not** from `/mnt/c/` |
| Extremely slow performance | Bind mounts across Windows ↔ WSL boundary | Store the project inside WSL2 home (`~/`), not on a Windows-mounted drive |
| Docker Desktop won't start | WSL2 or Hyper-V not enabled | Run `wsl --install` in PowerShell (admin), reboot, then install Docker Desktop |
| Socket permission error in WSL2 | Docker Desktop integration not enabled for your WSL distro | Docker Desktop → Settings → Resources → WSL Integration → enable your distro |

### macOS

| Problem | Cause | Fix |
|---------|-------|-----|
| Slow bind-mount performance | macOS filesystem sharing overhead | Upgrade to Docker Desktop 4.x+ and enable **VirtioFS** in Settings → General |
| Port 5000 conflict | macOS AirPlay Receiver uses port 5000 | Disable AirPlay Receiver in System Settings → General → AirDrop & Handoff, or remap the port in `.env` |
| `docker compose` not found | Docker CLI plugins not in PATH | Run `brew install docker-compose` or reinstall Docker Desktop |
| Containers OOM-killed during install | Docker Desktop default Memory below RedAmon minimum | Docker Desktop → Settings → Resources → Memory: set to 4 GB (8 GB with `--gvm`), then `./redamon.sh install` |
| `Cannot connect to the Docker daemon` | Docker Desktop not started | `open /Applications/Docker.app` and wait until the whale icon stops animating before running `./redamon.sh` |
| `Mounts denied` / `path not shared` | Repo cloned outside Docker Desktop's File Sharing allowlist | Clone the repo under `~/` (default-allowed), or add the custom path in Settings → Resources → File Sharing |
| SYN scans (naabu, masscan) miss hosts on the local LAN | `network_mode: host` joins Docker Desktop's LinuxKit VM, not the Mac's network | Expected on Docker Desktop. Internet targets work normally; for LAN scans, run RedAmon on a Linux host |
| Login fails after install with no error in logs | Non-interactive shell (CI, agents, some multiplexers) injected a `\u0001` SOH byte into the admin email/password prompt | Run `./redamon.sh create-admin` to (re)create the admin cleanly (`reset-password` only works once an admin already exists) |
| No admin prompt appeared at install / can't log in | Webapp was slow to come up on first boot (common with `--gvm` or a small VM), so the automatic admin prompt was skipped | Run `./redamon.sh create-admin` once the stack is up (`./redamon.sh status`); it waits for the webapp, then prompts. Safe to re-run |

---

## The graph page hangs, 502s, or Neo4j logs "network aborts"

These three symptoms usually appear together on a project with a very large
graph. They have distinct causes, so check them in this order.

| Symptom | Cause | Fix |
|---------|-------|-----|
| Neo4j logs `Increase in network aborts detected`, connection count climbs steadily | **Fixed in this release.** The webapp used to create a new Neo4j driver (and a new pool of up to 50 Bolt connections) on *every* production request, abandoning the previous one | Update. Confirm with `CALL dbms.listConnections()` — the count must stay flat while you reload the graph page, not climb |
| API requests sit in `[pending]` forever, no error, no timeout | **Fixed in this release.** The driver's connection timeouts only bound *acquiring* a connection, so an unbounded whole-graph query ran forever | Update. Tune with `NEO4J_QUERY_TIMEOUT_MS` (default 120000) if you legitimately run long analytical queries |
| HTTP 502 from nginx, `recv() failed (104: Connection reset by peer)` in its error log | The webapp container was OOM-killed mid-response. A reset with no timeout means the process died, rather than the request being slow | Check `./redamon.sh status` for OOM-killed containers and restart counts. Memory limits are sized from host RAM automatically; see [README.MEMORY_GOVERNOR.md](README.MEMORY_GOVERNOR.md) |
| Containers OOM-killed generally | Host genuinely too small, or limits pinned by hand in `.env` | `./redamon.sh status` shows the computed allocation and warns when a running container has drifted from it |

Useful checks:

```bash
./redamon.sh status                                    # OOM kills, restarts, allocation, disk
docker logs redamon-neo4j --tail 50 | grep -i abort    # Bolt connection aborts
docker inspect redamon-webapp --format '{{.RestartCount}} {{.State.OOMKilled}}'
```

---

## `./redamon.sh update` refuses to pull

RedAmon's own scans used to dirty the git checkout. `recon/` is bind mounted
read-write into the spawned recon container, and two of its **git-tracked** data
directories are re-downloaded there whenever their 24h cache expires:

| Path | Written by | Contents |
|------|-----------|----------|
| `recon/main_recon_modules/data/mitre_db/` | `add_mitre.py` | MITRE CVE/CAPEC/CWE database, 15 files |
| `recon/main_recon_modules/data/wappalyzer_cache/` | `http_probe.py` | Wappalyzer fingerprints, `technologies.json` |

So after a scan or two `git pull --ff-only` refused, and the error advised
`git commit -am 'local changes'`, which converts a self-healing dirty tree into
a **permanent** dead end: the checkout then has a commit the project does not
and a fast-forward can never happen again (issue #185).

`update` now restores both directories before pulling. Never commit files under
them; they are machine-local caches that every scan may rewrite.

| Symptom | Cause | Fix |
|---------|-------|-----|
| `Could not pull updates: the working tree has local changes` with **no** file list under it, and `git status` is clean | Not local changes at all: the branch has diverged. `git log --oneline origin/master..HEAD` shows a `local changes` commit | Update once from a version that has this fixed. If you are already stuck, see the one-time recovery below |
| Same error, **with** a list of modified files under `recon/main_recon_modules/data/` | **Fixed in this release.** `update` restored only a `.last_update` marker that had since been gitignored, so it was doing nothing while the database directories beside it were what actually drifted | Update. Never commit those files — they are re-downloaded on every scan |
| `Permission denied` writing `.torch-variant`, `.git/index`, or similar | An earlier `sudo ./redamon.sh …` or `sudo git …` left root-owned files in a user-owned checkout | `sudo chown -R "$(id -un):$(id -gn)" .`, then re-run **without** sudo. `update` now checks this up front rather than failing halfway |
| `Could not pull updates.` plus a `NOTE: 'git status' failed here` block | Another git process (an IDE, a hook, an interrupted command) holds `.git/index.lock`, or the index is corrupt. `update` deliberately refuses to auto-recover while it cannot read your working tree | Wait for the other git process to finish, or remove a stale `.git/index.lock` **only** if none is running. Do not `reset --hard` until `git status` works — it would discard uncommitted work nobody can see |
| `error: unable to unlink … Permission denied` on a file under `recon/main_recon_modules/data/` | The scan container creates those cache directories as **root** inside a user-owned checkout, so neither git nor you can replace the file | Same `chown`. `update` now warns about root-owned runtime files *before* a release that changes one makes the pull fail |

**One-time recovery if your checkout has already diverged.** The fix ships
inside `redamon.sh`, which is the file you cannot pull, so a checkout that is
already in this state needs one manual reset. It discards the bogus
`local changes` commit only; run `git log --oneline origin/master..HEAD` first
and copy anything of your own onto a branch if that list contains real work.

```bash
cd ~/redamon
sudo chown -R "$(id -un):$(id -gn)" .   # only if an earlier run used sudo
git fetch origin
git reset --hard origin/master
./redamon.sh update
```

From that release on, `update` recovers by itself: a diverging commit whose
files are **all** RedAmon runtime files is reset automatically and reported,
while a commit touching anything else stops the update with instructions that
keep your work.

The automatic reset is the only destructive step in `update`, and it is gated
four ways: the working tree must be clean, `git status` must be readable, every
file in the diverging commits must sit under a RedAmon runtime data directory,
and no path may contain a traversal. To disable it entirely and always recover
by hand, set `REDAMON_NO_AUTO_RESET=1`.
