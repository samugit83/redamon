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
| Containers killed (OOM) | Insufficient RAM | Increase swap or free memory — see [minimum requirements](../README.md#prerequisites) |
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
