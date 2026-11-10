#!/usr/bin/env bash
# Take the IP-hostnames lab down.
#
# Refuses while the orchestrator still carries a lab hook aimed at THIS lab
# (URLSCAN_API_BASE on 192.88.98.30, or 192.88.98.x in REDAMON_LAB_CDN_PREFIXES):
# with the bridge gone those addresses route to the internet. Restart it
# without the hooks first.
#
#   ./down.sh            refuse (exit 1) while such a hook is set
#   ./down.sh --force    stop the lab anyway; still exit 1 to flag the hook
#
# Reverts the host DNS only if the bridge link still has the lab DNS set;
# otherwise there is nothing to revert. generated/ is kept (certificates, run
# evidence); delete it to start over.
set -euo pipefail
cd "$(dirname "$0")"

force=0
[ "${1:-}" = "--force" ] && force=1

hooks=""
if docker inspect redamon-recon-orchestrator >/dev/null 2>&1; then
    # Names only: the values (and every other variable) never leave this pipe.
    hooks=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' redamon-recon-orchestrator \
        | grep -E '^(URLSCAN_API_BASE=http://192\.88\.98\.30|REDAMON_LAB_CDN_PREFIXES=.*192\.88\.98\.)' \
        | cut -d= -f1 | tr '\n' ' ' || true)
fi
if [ -n "$hooks" ]; then
    echo "[!][Down] the orchestrator still carries lab hook(s) aimed at this lab: $hooks" >&2
    echo "    restart it without them, from the repository root, in a shell where they are unset:" >&2
    echo "    env -u URLSCAN_API_BASE -u REDAMON_LAB_CDN_PREFIXES -u REDAMON_LAB_PROJECT_IDS \\" >&2
    echo "        docker compose up -d --no-deps recon-orchestrator" >&2
    [ "$force" = 1 ] || exit 1
fi

if id=$(docker network inspect -f '{{.Id}}' redamon_iphn_lab 2>/dev/null); then
    BR="br-${id:0:12}"
    if ! command -v resolvectl >/dev/null 2>&1; then
        echo "[*][Down] no resolvectl here: if host_dns_enable.sh ever ran, revert with: resolvectl revert $BR"
    elif resolvectl dns "$BR" 2>/dev/null | grep -q '192\.88\.98\.53'; then
        ./host_dns_disable.sh || {
            echo "[!][Down] could not revert the host DNS: run ./host_dns_disable.sh (or: resolvectl revert $BR)" >&2
        }
    else
        echo "[*][Down] $BR carries no lab DNS: nothing to revert"
    fi
fi

docker compose -p iphn --profile intra down --remove-orphans
echo "[+][Down] lab down. 192.88.98.0/24 may now route to the internet: no lab scans until ./up.sh runs again."
[ -z "$hooks" ]
