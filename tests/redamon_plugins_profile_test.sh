#!/usr/bin/env bash
# =============================================================================
# Plugin platform: compose wiring of the runner, the proxy and the overlay.
# Run:  bash tests/redamon_plugins_profile_test.sh
#
# WHY THIS MATTERS: plugin code is third-party code. The runner and the proxy
# must be isolated exactly as designed (master plan TD-04, TD-05): the proxy is
# the only door out of the plugins network and never joins `redamon`, where
# Postgres, Neo4j and the agent's unauthenticated routes live; both internal
# networks drop the host-side bridge address (`gateway_mode_ipv4: isolated`,
# experiment E1). And the platform's only change to the webapp lives in the
# overlay docker-compose.plugins.yml, which redamon.sh loads on every install,
# update and up after the plugin preflight passed.
#
# Hermetic: `docker compose config` resolves the files without a daemon; the
# compose files are fed on stdin and the env file is /dev/null, so neither the
# operator's .env nor a temp directory the Docker CLI may not see is involved.
# Exits 77 (cannot run, a gate failure) without docker compose or python3. The
# image checks run only when redamon-plugin-runner:latest exists.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PASS=0; FAIL=0
ok()  { PASS=$((PASS+1)); printf '  ok   %s\n' "$1"; }
bad() { FAIL=$((FAIL+1)); printf '  FAIL %s (got: %s want: %s)\n' "$1" "$2" "$3"; }
eq()  { if [[ "$2" == "$3" ]]; then ok "$1"; else bad "$1" "$2" "$3"; fi; }

# 77: the gate's "cannot run" code (redamon.sh _TEST_SHELL_CANNOT_RUN).
if ! command -v python3 >/dev/null 2>&1 || ! docker compose version >/dev/null 2>&1; then
    echo "  CANNOT RUN  docker compose or python3 unavailable (plugins compose wiring)"
    exit 77
fi

export POSTGRES_PASSWORD=test-only NEO4J_PASSWORD=test-only

# config <compose file text on stdin> [--profile plugins] [more -f files]: resolved JSON.
config_json() {
    docker compose --env-file /dev/null --project-directory "$REPO_ROOT" -f - "$@" config --format json 2>/dev/null
}
services() {
    docker compose --env-file /dev/null --project-directory "$REPO_ROOT" -f - "$@" config --services 2>/dev/null | sort | tr '\n' ' '
}
BASE="$(cat "$REPO_ROOT/docker-compose.yml")"
OVERLAY="$REPO_ROOT/docker-compose.plugins.yml"

# q <json> <python expression over `c` (the parsed config)>
q() {
    python3 -c 'import json,sys; c=json.load(sys.stdin); print(eval(sys.argv[1]))' "$2" <<<"$1"
}

echo "== the two services exist only under the plugins profile =="
OFF="$(services <<<"$BASE")"
ON="$(services --profile plugins <<<"$BASE")"
[[ " $OFF " != *" plugin-runner "* && " $OFF " != *" plugin-gateway "* ]] \
    && ok "without the profile neither service is listed" || bad "without the profile" "$OFF" "no plugin service"
[[ " $ON " == *" plugin-runner "* && " $ON " == *" plugin-gateway "* ]] \
    && ok "with --profile plugins both are listed" || bad "with the profile" "$ON" "both"

# What a plain `up` creates is what the resolved config without the profile lists.
NOPROF="$(config_json <<<"$BASE")"
eq "without the profile: no plugins volume" "$(q "$NOPROF" "'plugins' in c.get('volumes', {})" 2>/dev/null)" "False"
eq "without the profile: no plugin network" \
   "$(q "$NOPROF" "sorted(n for n in c.get('networks', {}) if n.startswith('plugins'))" 2>/dev/null)" "[]"

C="$(config_json --profile plugins <<<"$BASE")"
if [[ -z "$C" ]]; then
    bad "docker compose config resolves the file" "empty" "json"
    printf 'passed %d, failed %d\n' "$PASS" "$FAIL"; exit 1
fi

echo
echo "== both plugin networks are internal and isolate the host =="
for net in plugins-net plugins-edge; do
    eq "$net is internal" "$(q "$C" "c['networks']['$net'].get('internal')")" "True"
    eq "$net drops the host-side bridge address" \
       "$(q "$C" "c['networks']['$net'].get('driver_opts',{}).get('com.docker.network.bridge.gateway_mode_ipv4')")" "isolated"
done
eq "plugins-net has a fixed name" "$(q "$C" "c['networks']['plugins-net']['name']")" "redamon-plugins-net"
eq "plugins-edge has a fixed name" "$(q "$C" "c['networks']['plugins-edge']['name']")" "redamon-plugins-edge"

echo
echo "== the plugin networks never take a range the core networks are pinned to =="
# redamon.sh creates the plugin networks before the core `up`. Left to Docker, they took the
# first free /16s of its default pools (172.27, 172.28) and the core up then failed with
# "Pool overlaps with other one on this address space": 172.28 is pentest-net's, and
# redamon-network, pushed up a slot, took orchestrator-net's 172.29.
subnets() {   # <json> <network>: its fixed subnets, one per line
    q "$1" "'\n'.join(x.get('subnet','') for x in (c['networks']['$2'].get('ipam') or {}).get('config') or [])"
}
OVERLAPS='
import ipaddress, json, sys
c = json.load(sys.stdin)
fixed = {n: [ipaddress.ip_network(x["subnet"]) for x in (v.get("ipam") or {}).get("config") or [] if x.get("subnet")]
         for n, v in c.get("networks", {}).items()}
auto = [ipaddress.ip_network(p) for p in ("172.17.0.0/16", "172.18.0.0/15", "172.20.0.0/14", "172.24.0.0/14",
                                          "172.28.0.0/14", "192.168.0.0/16")]
out = []
for n in ("plugins-net", "plugins-edge"):
    for a in fixed.get(n, []):
        out += [f"{n} {a} overlaps {m} {b}" for m, nets in fixed.items() if m != n for b in nets if a.overlaps(b)]
        out += [f"{n} {a} is inside a Docker default pool ({p})" for p in auto if a.overlaps(p)]
print("\n".join(sorted(set(out))) or "none")
'
for net in plugins-net plugins-edge; do
    [[ -n "$(subnets "$C" "$net")" ]] && ok "$net has a fixed subnet ($(subnets "$C" "$net"))" \
        || bad "$net has a fixed subnet" "none (Docker picks one)" "an explicit ipam subnet"
done
eq "no plugin subnet overlaps another fixed subnet or Docker's default pools" \
   "$(python3 -c "$OVERLAPS" <<<"$C")" "none"

echo
echo "== a .env copied from .env.example =="
# Every compose command reads the whole file, profiles or not: one value compose cannot
# use breaks `up` for every operator who copied the example.
EXAMPLE="$(docker compose --env-file "$REPO_ROOT/.env.example" --project-directory "$REPO_ROOT" -f - --profile plugins \
    config --format json < "$REPO_ROOT/docker-compose.yml" 2>&1)"
eq "resolves, plugins profile included" "$(q "$EXAMPLE" "'ok'" 2>/dev/null || echo "${EXAMPLE:0:300}")" "ok"
eq "the runner keeps its default pids limit" "$(q "$EXAMPLE" "c['services']['plugin-runner']['pids_limit']" 2>/dev/null)" "256"

echo
echo "== the runner =="
R="c['services']['plugin-runner']"
eq "joins only plugins-net" "$(q "$C" "sorted($R['networks'])")" "['plugins-net']"
eq "mounts the plugins volume read-only at /plugins" \
   "$(q "$C" "[(v['source'],v['target'],v.get('read_only')) for v in $R.get('volumes',[])]")" "[('plugins', '/plugins', True)]"
eq "read-only root filesystem" "$(q "$C" "$R.get('read_only')")" "True"
eq "drops every capability" "$(q "$C" "$R.get('cap_drop')")" "['ALL']"
eq "adds back only SETUID, SETGID, KILL" "$(q "$C" "sorted($R.get('cap_add',[]))")" "['KILL', 'SETGID', 'SETUID']"
eq "an init reaps what killed plugin processes leave (zombies count against a UID's nproc)" \
   "$(q "$C" "$R.get('init')")" "True"
eq "has a /tmp tmpfs for the workers" "$(q "$C" "any(t.startswith('/tmp') for t in $R.get('tmpfs',[]))")" "True"
eq "memory, pids and cpu limits" "$(q "$C" "all(k in $R for k in ('mem_limit','pids_limit','cpus'))")" "True"
eq "the runner key comes from .env" "$(q "$C" "'PLUGIN_RUNNER_KEY' in $R['environment']")" "True"
eq "the call-token secret never reaches the runner" "$(q "$C" "'PLUGIN_CALL_TOKEN_SECRET' in $R['environment']")" "False"
eq "it reaches the Gateway through the proxy" "$(q "$C" "$R['environment']['PLUGIN_GATEWAY_URL']")" "http://plugin-gateway:7071"

echo
echo "== the proxy =="
P="c['services']['plugin-gateway']"
eq "joins exactly plugins-net and plugins-edge" "$(q "$C" "sorted($P['networks'])")" "['plugins-edge', 'plugins-net']"
eq "never joins the redamon network" "$(q "$C" "'redamon' in $P['networks']")" "False"
eq "read-only root filesystem" "$(q "$C" "$P.get('read_only')")" "True"
eq "drops every capability and adds none" "$(q "$C" "($P.get('cap_drop'), $P.get('cap_add'))")" "(['ALL'], None)"
eq "gets the action cap, so it never times out an action the runner still allows" \
   "$(q "$C" "$P['environment'].get('PLUGIN_ACTION_MAX_TIMEOUT') == $R['environment']['PLUGIN_ACTION_MAX_TIMEOUT']")" "True"
eq "runs the proxy entrypoint" "$(q "$C" "$P['command']")" "['python', '-m', 'gateway_proxy.proxy']"
eq "same image as the runner" "$(q "$C" "$P['image'] == $R['image'] == 'redamon-plugin-runner:latest'")" "True"
eq "same build as the runner (a missing image is built, never pulled)" \
   "$(q "$C" "$P['build'] == $R['build'] and $R['build']['context'].endswith('services/plugin_runner')")" "True"

echo
echo "== hardening and operations on both =="
for S in plugin-runner plugin-gateway; do
    X="c['services']['$S']"
    eq "$S: profile plugins" "$(q "$C" "$X.get('profiles')")" "['plugins']"
    eq "$S: no host port published" "$(q "$C" "$X.get('ports')")" "None"
    eq "$S: no no-new-privileges (experiment E2: it stops every exec on the reference host)" \
       "$(q "$C" "any('no-new-privileges' in str(o) for o in $X.get('security_opt',[]))")" "False"
    eq "$S: declares a healthcheck" "$(q "$C" "bool($X.get('healthcheck',{}).get('test'))")" "True"
    eq "$S: rotates its log" \
       "$(q "$C" "($X['logging']['driver'], 'max-size' in $X['logging']['options'], 'max-file' in $X['logging']['options'])")" \
       "('json-file', True, True)"
    eq "$S: restarts unless stopped" "$(q "$C" "$X.get('restart')")" "unless-stopped"
done
eq "runner healthcheck is the supervisor probe" \
   "$(q "$C" "c['services']['plugin-runner']['healthcheck']['test']")" "['CMD', 'python', '-m', 'supervisor.healthcheck']"
eq "proxy healthcheck is the proxy probe" \
   "$(q "$C" "c['services']['plugin-gateway']['healthcheck']['test']")" "['CMD', 'python', '-m', 'gateway_proxy.healthcheck']"

echo
echo "== the webapp gets every plugin setting (it has no env_file) =="
WEBAPP_VARS="PLUGINS_DIR PLUGIN_RUNNER_URL PLUGIN_RUNNER_KEY PLUGIN_CALL_TOKEN_SECRET \
PLUGINS_CATALOG_URL PLUGINS_DOWNLOAD_HOSTS PLUGINS_EXTRA_TRUSTED_KEYS PLUGIN_ACTION_MAX_TIMEOUT \
PLUGIN_ARCHIVE_MAX_BYTES PLUGIN_TRANSCRIPT_MAX_BYTES PLUGIN_DATA_MAX_ROWS PLUGIN_DATA_MAX_BYTES \
PLUGIN_DATA_MAX_VALUE_BYTES PLUGIN_DATA_MAX_ROWS_PER_OWNER PLUGIN_GATEWAY_CALLS_PER_TOKEN \
PLUGIN_LLM_DAILY_CALL_CAP PLUGINS_ALLOWED_ORIGIN PLUGIN_SKILL_TEXT_MAX_GROWTH"
missing=""
for v in $WEBAPP_VARS; do
    [[ "$(q "$C" "'$v' in c['services']['webapp']['environment']")" == "True" ]] || missing="$missing $v"
done
eq "every plugin variable is in the webapp environment" "${missing:-none}" "none"
eq "the webapp reaches the supervisor through the proxy" \
   "$(q "$C" "c['services']['webapp']['environment']['PLUGIN_RUNNER_URL']")" "http://plugin-gateway:7072"
eq "the webapp's plugins folder is outside /app" \
   "$(q "$C" "c['services']['webapp']['environment']['PLUGINS_DIR']")" "/data/plugins"

echo
echo "== base file alone: the webapp is wired exactly as before the platform (R-75) =="
WEB="c['services']['webapp']"
WIRING="(sorted($WEB['networks']), sorted((v['type'], v.get('source'), v['target'], v.get('read_only')) for v in $WEB.get('volumes',[])), $WEB.get('ports'), $WEB.get('image'))"
OFFC="$(config_json <<<"$BASE")"
eq "no plugin network on the webapp" "$(q "$OFFC" "[n for n in $WEB['networks'] if n.startswith('plugins')]")" "[]"
eq "nothing mounted at /data/plugins" "$(q "$OFFC" "[v for v in $WEB.get('volumes',[]) if v['target']=='/data/plugins' or v.get('source')=='plugins']")" "[]"
FORK="$(git -C "$REPO_ROOT" merge-base HEAD refs/heads/master 2>/dev/null || true)"
if [[ -n "$FORK" && "$FORK" != "$(git -C "$REPO_ROOT" rev-parse HEAD)" ]] \
        && OLD="$(git -C "$REPO_ROOT" show "$FORK:docker-compose.yml" 2>/dev/null)"; then
    eq "webapp networks, volumes, ports and image equal the fork point's (${FORK:0:8})" \
       "$(q "$OFFC" "$WIRING")" "$(q "$(config_json <<<"$OLD")" "$WIRING")"
else
    echo "  SKIP  golden against the fork point: HEAD is not on a branch ahead of master"
fi

echo
echo "== with the overlay: it adds plugins-edge and the volume, nothing else =="
eq "the overlay changes only the webapp" \
   "$(python3 -c 'import sys,json; import re; t=open(sys.argv[1]).read(); print(re.findall(r"^  ([a-z0-9-]+):$", t, re.M))' "$OVERLAY")" "['webapp']"
ONC="$(config_json -f "$OVERLAY" --profile plugins <<<"$BASE")"
eq "webapp joins redamon, orchestrator-net and plugins-edge" \
   "$(q "$ONC" "sorted($WEB['networks'])")" "['orchestrator-net', 'plugins-edge', 'redamon']"
eq "webapp never joins plugins-net" "$(q "$ONC" "'plugins-net' in $WEB['networks']")" "False"
eq "webapp mounts the plugins volume read-write at /data/plugins" \
   "$(q "$ONC" "[(v['source'], v.get('read_only')) for v in $WEB['volumes'] if v['target']=='/data/plugins']")" "[('plugins', None)]"
eq "the overlay keeps every other webapp volume" \
   "$(q "$ONC" "len($WEB['volumes']) - 1")" "$(q "$OFFC" "len($WEB['volumes'])")"
DEVC="$(config_json -f "$REPO_ROOT/docker-compose.dev.yml" -f "$OVERLAY" <<<"$BASE")"
eq "up dev: the plugins volume stays outside the ./webapp bind mount (R-80)" \
   "$(q "$DEVC" "[v['target'] for v in $WEB['volumes'] if v.get('source')=='plugins']")" "['/data/plugins']"
eq "up dev: nothing under /app/plugins" \
   "$(q "$DEVC" "[v['target'] for v in $WEB['volumes'] if v['target'].startswith('/app/plugins')]")" "[]"

echo
echo "== the images pre-create the volume's mount point for uid 1001 (X22) =="
grep -qE '^RUN mkdir -p /data/plugins && chown nextjs:nodejs /data/plugins$' "$REPO_ROOT/webapp/Dockerfile" \
    && ok "webapp/Dockerfile pre-chowns /data/plugins" || bad "webapp/Dockerfile pre-chowns /data/plugins" "absent" "present"
IMG=redamon-plugin-runner:latest
if docker image inspect "$IMG" >/dev/null 2>&1; then
    eq "no setuid or setgid file in the runner image (E2)" \
       "$(docker run --rm --entrypoint sh "$IMG" -c 'find / -xdev -perm /6000 -type f 2>/dev/null' | tr '\n' ' ')" ""
    eq "/plugins belongs to 1001:1001, mode 755" \
       "$(docker run --rm --entrypoint stat "$IMG" -c '%u:%g %a' /plugins)" "1001:1001 755"
    eq "no file of the runner is writable by others" \
       "$(docker run --rm --entrypoint sh "$IMG" -c 'find /opt/runner -perm -o+w | head -3' | tr '\n' ' ')" ""
    # The source's version, so a rebuilt image is checked against the tree it was built from.
    want_platform=$(sed -n 's/^PLATFORM_VERSION = "\(.*\)"$/\1/p' "$REPO_ROOT/services/plugin_runner/platform_version.py")
    eq "the image reports platform $want_platform (services/plugin_runner/platform_version.py)" \
       "$(docker run --rm --entrypoint python "$IMG" -c 'import platform_version; print(platform_version.PLATFORM_VERSION)')" "$want_platform"
else
    echo "  SKIP  $IMG is not built (docker compose build plugin-runner)"
fi

echo
printf 'passed %d, failed %d\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]]
