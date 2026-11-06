#!/usr/bin/env bash
# Take the urlscan lab down.
#
# Refuses while the orchestrator still carries a lab hook: it would keep sending
# the listed projects' urlscan searches (and their key) to an address that, with
# the bridge gone, routes to the internet. Restart it without the hooks first.
#
#   ./down.sh            refuse (exit 1) while a hook is set
#   ./down.sh --force    revert the DNS and stop the lab anyway; still exit 1 to flag the hook
#
# Always reverts the host DNS hookup, run T's ~herokuapp.com included.
# generated/ is kept (tokens, fixtures, run evidence); delete it to start over.
set -euo pipefail
cd "$(dirname "$0")"

force=0
[ "${1:-}" = "--force" ] && force=1

hooks=""
if docker inspect redamon-recon-orchestrator >/dev/null 2>&1; then
    # Names only: the values (and every other variable) never leave this pipe.
    hooks=$(docker inspect -f '{{range .Config.Env}}{{println .}}{{end}}' redamon-recon-orchestrator \
        | grep -E '^(URLSCAN_API_BASE|REDAMON_LAB_CDN_PREFIXES|REDAMON_LAB_PROJECT_IDS)=.+' \
        | cut -d= -f1 | tr '\n' ' ' || true)
fi
if [ -n "$hooks" ]; then
    echo "[!] the orchestrator still carries the lab hook(s): $hooks" >&2
    echo "    restart it without them, from the repository root, in a shell where they are unset:" >&2
    echo "    env -u URLSCAN_API_BASE -u REDAMON_LAB_CDN_PREFIXES -u REDAMON_LAB_PROJECT_IDS \\" >&2
    echo "        docker compose up -d --no-deps recon-orchestrator" >&2
    if [ "$force" = 0 ]; then
        exit 1
    fi
fi

./host_dns_disable.sh || echo "[!] could not revert the host DNS: run ./host_dns_disable.sh by hand" >&2
docker compose -p uslab down --remove-orphans
echo "[+] lab down. 192.88.97.0/24 may now route to the internet: no lab scans until ./up.sh runs again."
[ -z "$hooks" ]
