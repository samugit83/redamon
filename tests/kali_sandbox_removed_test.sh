#!/usr/bin/env bash
# =============================================================================
# The shared Kali sandbox is gone (group 1, S21: T5, T7, I9, I10, D16, D22, E3,
# D24, S5, S7, I11, E4). Each person gets their own sandbox, started by the
# orchestrator from the image; nothing runs the old shared container any more.
# Run:  bash tests/kali_sandbox_removed_test.sh
#
#   - compose: `kali-sandbox` is build-only (`profiles: ["tools"]` and the image
#     tag; the service name stays because an older deploy overlay still names it);
#     no compose file publishes 4444; the agent has no MCP_*_URL,
#     KALI_TERMINAL_WS_URL, MCP_AUTH_TOKEN or `depends_on: kali-sandbox`; the
#     webapp has no TUNNEL_AUTH_TOKEN; the orchestrator no KALI_SANDBOX_MODE;
#   - no code dials a `kali-sandbox` address (agentic/, webapp/src, mcp/servers);
#   - redamon.sh: no Kali service in CORE_SERVICES / CORE_BUILD_SERVICES, the image
#     in TOOL_IMAGES, `KALI:100:1024:p`, nothing exports KALI_MEM or KALI_CPUS,
#     `_REMOVED_CONTAINERS` does not name redamon-kali;
#   - `_retire_shared_kali` runs in install, up, up dev and down before compose,
#     and in update only after every build and after the preview's answer (an
#     `update --preview`, an operator's no and a disk-gate stop leave it alone);
#   - the update map: mcp/kali-sandbox/ and mcp/requirements.txt rebuild the tool
#     image, mcp/servers/ rebuilds and restarts nothing, a missing image is built;
#   - `_kali_msf_refresh`: once a day, its own stamp, a failed build only warns,
#     never in --preview or an update with nothing to pull, never the full gate;
#   - the deploy overlay of the previous release (tests/fixtures/
#     deploy_overlay_v7.9.0/, a verbatim copy) still renders against this base.
#
# redamon.sh is sourced (its BASH_SOURCE guard stops the dispatch); the real
# cmd_update runs against a stubbed `docker`, `git` and `compose_build`, as
# tests/redamon_rbac_preview_test.sh does. Exits 77 (the gate's "cannot run")
# when an input is missing: python3 with PyYAML, docker compose (for the render).
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="$REPO_ROOT/docker-compose.yml"
PROD="$REPO_ROOT/tooling/deploy/single-host/compose/docker-compose.prod.yml"
OLD_PROD="$REPO_ROOT/tests/fixtures/deploy_overlay_v7.9.0/docker-compose.prod.yml"
for f in "$REPO_ROOT/redamon.sh" "$COMPOSE" "$PROD" "$OLD_PROD"; do
    [[ -f "$f" ]] || { echo "CANNOT RUN: $f is missing"; exit 77; }
done
python3 -c 'import yaml' 2>/dev/null || { echo "CANNOT RUN: python3 with PyYAML is needed"; exit 77; }

PASS=0; FAIL=0; CANNOT=""
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3')"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3')"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }
report() {  # <label> <violations>
    if [[ -z "$2" ]]; then pass "$1"; else fail "$1"; printf '%s\n' "$2" | sed 's/^/        /' | head -20; fi
}
expect_caught() {  # <label> <violations>
    if [[ -n "$2" ]]; then pass "$1"; else fail "$1 (a planted violation was not found)"; fi
}
# ascending <label> <n1> <n2> ...: every number present and strictly increasing.
ascending() {
    local label="$1" prev="" n; shift
    for n in "$@"; do
        if [[ -z "$n" || ( -n "$prev" && "$n" -le "$prev" ) ]]; then fail "$label (lines: $*)"; return; fi
        prev="$n"
    done
    pass "$label"
}

TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

# =============================================================================
# Violations of the compose rules, one per line, for the base file ($1) and the
# overlays after it. `!override`/`!reset` tags are read as plain values.
compose_violations() {
    python3 - "$@" <<'PY'
import re, sys, yaml

class Loader(yaml.SafeLoader):
    pass
Loader.add_multi_constructor("!", lambda l, s, n: (
    l.construct_mapping(n) if isinstance(n, yaml.MappingNode)
    else l.construct_sequence(n) if isinstance(n, yaml.SequenceNode)
    else l.construct_scalar(n)))

def env_names(env):
    if isinstance(env, dict):
        return set(env)
    return {str(e).split("=", 1)[0] for e in (env or [])}

def publishes_4444(entry):
    if isinstance(entry, dict):
        return 4444 in {int(str(entry.get(k)).split("/")[0]) for k in ("target", "published")
                        if str(entry.get(k) or "").split("/")[0].isdigit()}
    parts = re.split(r":", str(entry).split("/")[0])
    return "4444" in parts[-2:]

def deps(svc):
    d = svc.get("depends_on") or []
    return set(d) if isinstance(d, (dict, list)) else set()

URL = re.compile(r"(https?|wss?)://kali-sandbox[:/]")
base, overlays = sys.argv[1], sys.argv[2:]
for i, path in enumerate([base] + overlays):
    name = path.rsplit("/", 1)[-1] if i else "base"
    doc = yaml.load(open(path, encoding="utf-8"), Loader=Loader) or {}
    services = doc.get("services") or {}
    for sname, svc in services.items():
        svc = svc or {}
        for p in svc.get("ports") or []:
            if publishes_4444(p):
                print(f"{name}: {sname} publishes 4444 ({p})")
        if "kali-sandbox" in deps(svc):
            print(f"{name}: {sname} depends on kali-sandbox")
        env = svc.get("environment") or {}
        values = env.values() if isinstance(env, dict) else env
        for v in values:
            if URL.search(str(v)):
                print(f"{name}: {sname} names a kali-sandbox address ({v})")
    agent = services.get("agent") or {}
    agent_env = agent.get("environment") or {}
    if not isinstance(agent_env, dict):
        agent_env = dict(str(e).split("=", 1) if "=" in str(e) else (str(e), None) for e in agent_env)
    for var in sorted(agent_env):
        if re.fullmatch(r"MCP_[A-Z0-9_]*_URL|KALI_TERMINAL_WS_URL", var):
            print(f"{name}: agent still has {var}")
        # The two old tokens stay in .env for the deploy's secrets gate; the agent's
        # env_file would hand them over, so its environment blanks them.
        if var in ("MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN") and agent_env[var] not in ("", None):
            print(f"{name}: agent gets {var} with a value")
    if not i:
        for var in ("MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN"):
            if agent_env.get(var, "missing") != "":
                print(f"base: the agent's environment does not blank {var} (its env_file is .env)")
    if "TUNNEL_AUTH_TOKEN" in env_names((services.get("webapp") or {}).get("environment")):
        print(f"{name}: webapp still has TUNNEL_AUTH_TOKEN")
    if "KALI_SANDBOX_MODE" in env_names((services.get("recon-orchestrator") or {}).get("environment")):
        print(f"{name}: recon-orchestrator still has KALI_SANDBOX_MODE")
    if i and "kali-sandbox" in services:
        print(f"{name}: the overlay still re-lists kali-sandbox")
    if not i:
        kali = services.get("kali-sandbox")
        if not isinstance(kali, dict):
            print("base: no kali-sandbox service (the build of the image, and older overlays, need it)")
            continue
        extra = sorted(set(kali) - {"build", "image", "profiles"})
        if extra:
            print(f"base: kali-sandbox is not build-only, it also has {extra}")
        if kali.get("profiles") != ["tools"]:
            print(f"base: kali-sandbox profiles {kali.get('profiles')!r}, not ['tools']")
        if kali.get("image") != "redamon-kali-sandbox:latest":
            print(f"base: kali-sandbox image {kali.get('image')!r}")
        args = (kali.get("build") or {}).get("args") or {}
        if args.get("MSF_REFRESH_STAMP") != "${MSF_REFRESH_STAMP:-}":
            print(f"base: kali-sandbox build args {args!r}")
PY
}

section "compose: no running Kali service, no 4444, no shared address or token"
OVERLAYS=()
for f in "$REPO_ROOT"/docker-compose.dev.yml "$REPO_ROOT"/docker-compose.gpu.yml \
         "$REPO_ROOT"/docker-compose.plugins.yml "$PROD"; do
    [[ -f "$f" ]] && OVERLAYS+=("$f")
done
report "docker-compose.yml and its overlays" "$(compose_violations "$COMPOSE" "${OVERLAYS[@]}")"

python3 - "$COMPOSE" "$TMP/planted.yml" <<'PY'
import sys
src = open(sys.argv[1], encoding="utf-8").read()
src = src.replace("    image: redamon-ai-attack-surface:latest\n",
                  "    image: redamon-ai-attack-surface:latest\n    ports:\n      - \"0.0.0.0:4444:4444/tcp\"\n", 1)
src = src.replace('      MCP_AUTH_TOKEN: ""\n', "      MCP_AUTH_TOKEN: x\n", 1)
open(sys.argv[2], "w", encoding="utf-8").write(src)
PY
planted="$(compose_violations "$TMP/planted.yml")"
expect_caught "a planted 4444 publish is caught" "$(grep 4444 <<< "$planted")"
expect_caught "a planted agent MCP_AUTH_TOKEN is caught" "$(grep MCP_AUTH_TOKEN <<< "$planted")"
printf 'services:\n  kali-sandbox:\n    ports: !override\n      - "127.0.0.1:4444:4444"\n' > "$TMP/overlay.yml"
expect_caught "an overlay re-listing kali-sandbox is caught" "$(compose_violations "$COMPOSE" "$TMP/overlay.yml")"

python3 - "$REPO_ROOT/mcp/docker-compose.yml" > "$TMP/standalone.txt" <<'PY'
import sys, yaml
path = sys.argv[1]
try:
    doc = yaml.safe_load(open(path, encoding="utf-8")) or {}
except FileNotFoundError:
    sys.exit(0)
for name, svc in (doc.get("services") or {}).items():
    svc = svc or {}
    if svc.get("container_name") == "redamon-kali" or name == "redamon-kali":
        print(f"{name}: named redamon-kali (_retire_shared_kali and the live stack's name)")
    for p in svc.get("ports") or []:
        if not str(p).startswith("127.0.0.1:"):
            print(f"{name}: publishes {p} off loopback")
    if "SYS_PTRACE" in (svc.get("cap_add") or []):
        print(f"{name}: has SYS_PTRACE")
    for v in svc.get("volumes") or []:
        src, _, rest = str(v).partition(":")
        if src.rstrip("/") == "./output":
            print(f"{name}: mounts the whole ./output (every person's users/<key>)")
        if src.rstrip("/") == "./servers" and not rest.endswith(":ro"):
            print(f"{name}: mounts ./servers read-write")
PY
report "mcp/docker-compose.yml (standalone server work) is loopback-only, unprivileged, its own output" "$(cat "$TMP/standalone.txt")"

section "no code dials a kali-sandbox address"
# Tests are left out: some assert that nothing calls the old address.
hits="$(cd "$REPO_ROOT" && grep -rnE '(https?|wss?)://kali-sandbox[:/]' agentic webapp/src mcp/servers \
        --include='*.py' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.sh' 2>/dev/null \
        | grep -vE '(^|/)(tests?|__tests__|node_modules)/|\.test\.tsx?:|(^|/)test_[^/]*\.py:|_test\.sh:|conftest\.py:' || true)"
report "agentic/, webapp/src, mcp/servers" "$hits"
# Nor names it as a bare host (a fallback such as `or "kali-sandbox"`): no container
# answers to that name any more. The one exception is the contract's SELF_NAME, the
# name a sandbox resolves to itself through its own /etc/hosts (EXTRA_HOSTS), never
# a host the agent dials.
hits="$(cd "$REPO_ROOT" && grep -rnE "[\"'\`]kali-sandbox[\"'\`]" agentic webapp/src mcp/servers \
        --include='*.py' --include='*.ts' --include='*.tsx' --include='*.js' --include='*.mjs' --include='*.sh' 2>/dev/null \
        | grep -vE '(^|/)(tests?|__tests__|node_modules)/|\.test\.tsx?:|(^|/)test_[^/]*\.py:|_test\.sh:|conftest\.py:' \
        | grep -vxE 'agentic/sandbox_contract\.py:[0-9]+:SELF_NAME = "kali-sandbox"' || true)"
report "no code names kali-sandbox as a host" "$hits"
self_uses="$(cd "$REPO_ROOT" && grep -rnwE 'SELF_NAME' agentic webapp/src mcp/servers --include='*.py' --include='*.ts' --include='*.tsx' 2>/dev/null \
        | grep -vE '(^|/)tests?/|\.test\.tsx?:' | grep -vE '^agentic/sandbox_contract\.py:[0-9]+:(SELF_NAME = |EXTRA_HOSTS = MappingProxyType\(\{SELF_NAME: "127\.0\.0\.1"\}\))' || true)"
report "the contract's SELF_NAME is only the sandbox's own /etc/hosts name" "$self_uses"

# =============================================================================
# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e
info() { printf 'INFO %s\n' "$*"; }
warn() { printf 'WARN %s\n' "$*"; }
error() { :; }
success() { :; }

section "redamon.sh: the service lists and the memory spec"
assert_not_contains "CORE_SERVICES names no Kali service" "$CORE_SERVICES" "kali"
assert_not_contains "CORE_BUILD_SERVICES names no Kali service" "$CORE_BUILD_SERVICES" "kali"
assert_contains "TOOL_IMAGES has the Kali image (ensure_tool_images builds it when missing)" \
    " $TOOL_IMAGES " " redamon-kali-sandbox:latest "
assert_contains "_MEM_SPECS_BASE holds KALI:100:1024:p" " $_MEM_SPECS_BASE " " KALI:100:1024:p "
assert_not_contains "_REMOVED_CONTAINERS does not name redamon-kali" " ${_REMOVED_CONTAINERS[*]} " " redamon-kali "

section "nothing exports KALI_MEM or KALI_CPUS"
SCRIPT_DIR="$TMP/envdir"; mkdir -p "$SCRIPT_DIR"
detect_build_resources() { BUILD_MEM_MB="${STUB_MEM:-16384}"; BUILD_RES_SOURCE=stub; BUILD_NCPU=16; }
is_gvm_enabled() { return 1; }
is_kbase_enabled() { return 1; }
export BURST_FACTOR=1.75
for STUB_MEM in 8192 16384 65536; do
    unset KALI_MEM KALI_CPUS; _MEM_SELF_EXPORTED=" "
    allocate_memory >/dev/null
    assert_eq "${STUB_MEM}MB: KALI_MEM not exported" "${KALI_MEM:-<unset>}" "<unset>"
done
assert_not_contains "the managed vars do not list KALI_MEM" "$(_mem_managed_vars | tr '\n' ' ')" "KALI_MEM"
STUB_MEM=16384; _MEM_SELF_EXPORTED=" "; allocate_memory >/dev/null; persist_memory_env
assert_not_contains "the managed .env block has no KALI_MEM" "$(cat "$SCRIPT_DIR/.env")" "KALI_MEM"
unset KALI_CPUS; export_cpu_caps
assert_eq "export_cpu_caps leaves KALI_CPUS unset" "${KALI_CPUS:-<unset>}" "<unset>"
assert_eq "no line of redamon.sh exports or caps KALI_CPUS" \
    "$(grep -vE '^[[:space:]]*#' "$REPO_ROOT/redamon.sh" | grep -cE '_export_cpu_cap[[:space:]]+KALI_CPUS|(^|[^A-Z_])KALI_CPUS=')" "0"
# An operator's pin is ignored, and said so once per run.
rm -f "$SCRIPT_DIR/.env"; _MEM_SELF_EXPORTED=" "; _MEM_POOL_PIN_NOTED=""
out="$(KALI_MEM=6g allocate_memory; KALI_MEM=6g allocate_memory)"
assert_eq "a KALI_MEM in the shell is ignored with one info line" \
    "$(grep -c 'KALI_MEM' <<< "$out")" "1"
printf 'KALI_MEM=6g\n' > "$SCRIPT_DIR/.env"; _MEM_POOL_PIN_NOTED=""
out="$(unset KALI_MEM; allocate_memory)"
assert_contains "a KALI_MEM pinned in .env is named as ignored" "$out" "KALI_MEM"
_MEM_SELF_EXPORTED=" "; allocate_memory >/dev/null; persist_memory_env
assert_eq "the operator's line is left as it is" "$(grep -c '^KALI_MEM=6g$' "$SCRIPT_DIR/.env")" "1"
assert_eq "and the block adds none" "$(grep -c '^KALI_MEM=' "$SCRIPT_DIR/.env")" "1"
SCRIPT_DIR="$REPO_ROOT"; unset BURST_FACTOR

section "the agent gets no Kali leftover through its env_file (.env)"
# The agent's env_file is .env, so what redamon.sh leaves there reaches it. The two
# old tokens stay (the single-host deploy's secrets gate refuses a .env without
# them) and the agent's environment blanks them; the dead Kali knobs leave .env.
D="$(mktemp -d "$REPO_ROOT/.s21-envfile.XXXXXX")"
cat > "$D/.env" <<'ENV'
NEO4J_PASSWORD=s21-dummy-neo4j
POSTGRES_PASSWORD=s21-dummy-postgres
MCP_AUTH_TOKEN=s21-stale-mcp-token-value-0000000000
TUNNEL_AUTH_TOKEN=s21-stale-tunnel-token-value-000000
KALI_SANDBOX_MODE=shared
KALI_MEM=6g
KALI_PIDS=4096
export KALI_CPUS=10
# >>> redamon memory governor (auto) >>>
KALI_MEM=1617m
# <<< redamon memory governor <<<
ENV
# An operator's pins stay where they are (a roll-back needs them, and --preview and
# the gates write nothing): each is named as ignored, once per run.
before="$(cksum < "$D/.env")"
out="$(SCRIPT_DIR="$D" _env_note_retired_kali_keys; SCRIPT_DIR="$D" _env_note_retired_kali_keys)"
assert_eq ".env is left byte for byte" "$(cksum < "$D/.env")" "$before"
assert_eq "one ignored line per retired key, once per run (KALI_MEM is the allocator's)" \
    "$(grep -c '^INFO .*ignored' <<< "$out")" "3"
for k in KALI_SANDBOX_MODE KALI_PIDS KALI_CPUS; do
    assert_contains "$k is named" "$out" "$k"
done
assert_eq "nothing names a removal" "$(grep -ci 'removed' <<< "$out")" "0"
assert_eq "nothing removes them from .env" "$(type -t _env_drop_retired_kali_keys)" ""
hook="$(sed -n '/^case "\${1:-help}" in$/,/^esac$/p' "$REPO_ROOT/redamon.sh" | grep -E '^[[:space:]]*install\|update\|up\)')"
assert_contains "install, update and up name them" "$hook" "_env_note_retired_kali_keys"
if docker_bin="$(type -P docker)" && "$docker_bin" compose version >/dev/null 2>&1; then
    printf 'KALI_SANDBOX_MODE=shared\nKALI_MEM=6g\n' >> "$D/.env"   # an operator adding one back by hand
    agent_env="$(cd "$D" && env -u COMPOSE_FILE -u COMPOSE_PROFILES "$docker_bin" compose --project-directory "$D" \
        -f "$REPO_ROOT/docker-compose.yml" --env-file "$D/.env" config --format json 2>/dev/null \
        | python3 -c 'import json, sys; e = json.load(sys.stdin)["services"]["agent"]["environment"]
for k in ("MCP_AUTH_TOKEN", "TUNNEL_AUTH_TOKEN"): print(k, repr(e.get(k)))' 2>/dev/null)"
    assert_eq "rendered with a .env holding both tokens, the agent gets them empty" "$agent_env" \
        "MCP_AUTH_TOKEN ''"$'\n'"TUNNEL_AUTH_TOKEN ''"
else
    CANNOT="docker compose is not available (the agent's rendered environment)"
fi
rm -rf "$D"

# =============================================================================
section "_retire_shared_kali"
CALLS="$TMP/calls"
SHARED_EXISTS=0; SHARED_PROJECT=myproj
export COMPOSE_PROJECT_NAME=myproj
docker() {
    printf 'docker %s\n' "$*" >> "$CALLS"
    if [[ "$1 ${2:-}" == "container inspect" ]]; then
        [[ "$SHARED_EXISTS" == 1 && "${*: -1}" == "redamon-kali" ]] || return 1
        printf '/redamon-kali %s\n' "$SHARED_PROJECT"
    fi
    return 0
}
: > "$CALLS"; SHARED_EXISTS=1
out="$(_retire_shared_kali)"
assert_contains "the shared container is removed" "$(cat "$CALLS")" "docker rm -f redamon-kali"
assert_eq "with one info line" "$(grep -c '^INFO' <<< "$out")" "1"
# Another stack's (a test stack, an export run from elsewhere on the same daemon).
for SHARED_PROJECT in some-test-stack ""; do
    : > "$CALLS"
    out="$(_retire_shared_kali)"
    assert_eq "another compose project's redamon-kali ('${SHARED_PROJECT:-no label}') is left alone" \
        "$(grep -c '^docker rm' "$CALLS")" "0"
done
SHARED_PROJECT=myproj
: > "$CALLS"; SHARED_EXISTS=0
out="$(_retire_shared_kali)"
assert_eq "absent: nothing is removed" "$(grep -c '^docker rm' "$CALLS")" "0"
assert_eq "absent: nothing is said" "$out" ""
assert_not_contains "only the exact name, never a per-user sandbox" "$(declare -f _retire_shared_kali)" "name=redamon-kali"

# Before compose starts or stops anything (compose skips the containers of a
# service whose profile is not active, so `down` would leave it running).
order_before() {  # <label> <function> <pattern of the compose call>
    local body a b
    body="$(declare -f "$2")"
    a="$(grep -n '_retire_shared_kali' <<< "$body" | head -n1 | cut -d: -f1)"
    b="$(grep -nE -- "$3" <<< "$body" | head -n1 | cut -d: -f1)"
    ascending "$1" "$a" "$b"
}
order_before "install retires it before its first compose up" cmd_install 'gvm_up_or_diagnose|docker compose up'
order_before "up retires it before compose up" cmd_up 'gvm_up_or_diagnose|docker compose up'
order_before "up dev retires it before compose up" cmd_up_dev 'docker compose .*up -d'
order_before "down retires it before compose down" cmd_down 'docker compose .*down'
body="$(declare -f cmd_install)"
for pat in 'gvm_up_or_diagnose --force-recreate' 'docker compose up -d --force-recreate'; do
    a="$(grep -n '_retire_shared_kali' <<< "$body" | head -n1 | cut -d: -f1)"
    b="$(grep -nF -- "$pat" <<< "$body" | head -n1 | cut -d: -f1)"
    ascending "install: before '$pat'" "$a" "$b"
done
# A sandbox the orchestrator starts while compose is stopping it would survive the
# first removal: each command removes the spawned containers again after its down.
for f in cmd_down cmd_clean cmd_purge; do
    body="$(declare -f "$f")"
    ascending "$f removes the spawned containers again after compose down" \
        "$(grep -nE 'docker compose .*down' <<< "$body" | head -n1 | cut -d: -f1)" \
        "$(grep -n 'remove_spawned_containers' <<< "$body" | tail -n1 | cut -d: -f1)"
done
ascending "purge removes the sandbox networks after that second removal" \
    "$(grep -n 'remove_spawned_containers' <<< "$(declare -f cmd_purge)" | tail -n1 | cut -d: -f1)" \
    "$(grep -n '_purge_kali_sandbox_resources' <<< "$(declare -f cmd_purge)" | tail -n1 | cut -d: -f1)"
assert_not_contains "the dispatch does not retire it (it runs before update's builds)" \
    "$(sed -n '/^case "\${1:-help}" in/,/^esac/p' "$REPO_ROOT/redamon.sh")" "_retire_shared_kali"

# =============================================================================
section "the pentest network is created now that no default service is on it"
# The orchestrator starts the capture proxy on it and the labs name it external;
# compose creates a network only for the services it starts, and the capture
# proxy's profile is not one.
NETS=""; NET_INFO=""; CREATE_RC=0; OTHER_NETS=""
docker() {
    printf 'docker %s\n' "$*" >> "$CALLS"
    case "$1 ${2:-}" in
        "network inspect")
            local n="${*: -1}" entry
            if [[ " $NETS " == *" $n "* ]]; then
                [[ "$*" == *com.docker.compose.project* ]] && printf '%s\n' "${NET_INFO:-myproj|pentest-net|172.28.0.0/16}"
                return 0
            fi
            for entry in $OTHER_NETS; do
                [[ "${entry%%=*}" == "$n" ]] && { printf '%s \n' "${entry#*=}"; return 0; }
            done
            return 1 ;;
        "network ls") for entry in $NETS $OTHER_NETS; do printf '%s\n' "${entry%%=*}"; done ;;
        "network create") return "$CREATE_RC" ;;
        "compose version") echo 5.7.2 ;;
    esac
    return 0
}
: > "$CALLS"; NETS=""
out="$(_ensure_pentest_net)"
create="$(grep '^docker network create' "$CALLS")"
assert_contains "missing: created with compose's name" "$create" " myproj_pentest-net"
assert_contains "its subnet from docker-compose.yml" "$create" "--subnet $(awk '/^networks:/ { n = 1 } n && /^  pentest-net:/ { p = 1; next } p && /subnet:/ { print $NF; exit }' "$REPO_ROOT/docker-compose.yml")"
assert_contains "the compose project label" "$create" "--label com.docker.compose.project=myproj"
assert_contains "the compose network label" "$create" "--label com.docker.compose.network=pentest-net"
assert_contains "said so" "$out" "Created the myproj_pentest-net network"
: > "$CALLS"; NETS="myproj_pentest-net"
out="$(_ensure_pentest_net)"
assert_eq "present and as compose describes it: nothing is created" "$(grep -c '^docker network create' "$CALLS")" "0"
assert_eq "and nothing is said" "$out" ""
NET_INFO="otherproj|pentest-net|172.28.0.0/16"; out="$(_ensure_pentest_net)"
assert_contains "another project's labels: warned, with the labels it has" "$out" "otherproj|pentest-net|172.28.0.0/16"
assert_contains "and the remedy: remove it, then up" "$out" "docker network rm myproj_pentest-net"
NET_INFO="||172.28.0.0/16"; out="$(_ensure_pentest_net)"
assert_contains "no compose labels (a hand-made one): warned" "$out" "WARN"
NET_INFO="myproj|pentest-net|10.9.0.0/16"; out="$(_ensure_pentest_net)"
assert_contains "another subnet: warned" "$out" "10.9.0.0/16"
NET_INFO=""
: > "$CALLS"; NETS=""; CREATE_RC=1; OTHER_NETS="mcp_pentest-net=172.28.0.0/16"
out="$(_ensure_pentest_net)"
assert_contains "the subnet held by the old standalone mcp network: named" "$out" "mcp_pentest-net"
assert_contains "with how to remove it" "$out" "docker network rm mcp_pentest-net"
OTHER_NETS="labnet=172.28.0.0/16"; out="$(_ensure_pentest_net)"
assert_contains "held by any other network: named" "$out" "labnet"
OTHER_NETS=""; out="$(_ensure_pentest_net)"
assert_contains "a create that fails for another reason: warned" "$out" "WARN"
for o in "$(OTHER_NETS="mcp_pentest-net=172.28.0.0/16" _ensure_pentest_net)" "$out"; do
    assert_not_contains "no remedy suggests a label-less docker network create" "$o" "docker network create"
done
CREATE_RC=0
for f in cmd_install cmd_up cmd_up_dev; do
    order_before_net() {
        local body a b
        body="$(declare -f "$1")"
        a="$(grep -n '_ensure_pentest_net' <<< "$body" | head -n1 | cut -d: -f1)"
        b="$(grep -nE 'gvm_up_or_diagnose|docker compose .*up -d' <<< "$body" | head -n1 | cut -d: -f1)"
        ascending "$1 creates it before compose up" "$a" "$b"
    }
    order_before_net "$f"
done
assert_contains "update creates it (before the recreate)" "$(declare -f cmd_update)" "_ensure_pentest_net"
assert_contains "an update with nothing to pull too" \
    "$(declare -f cmd_update | sed -n '/Already up to date/,/return/p')" "_ensure_pentest_net"
assert_contains "purge removes it (no profile of its down names it)" "$(declare -f cmd_purge)" '_pentest-net'
# The real daemon: a throwaway project's network as created here is the one compose
# adopts for that project's capture-profile service.
unset -f docker
if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
    P="s21pnet$$"; ND="$(mktemp -d "$REPO_ROOT/.s21-pnet.XXXXXX")"
    printf 'services:\n  proxy:\n    image: busybox\n    profiles: ["capture"]\n    networks: [pentest-net]\nnetworks:\n  pentest-net:\n    driver: bridge\n    ipam:\n      config:\n        - subnet: 10.213.93.0/28\n' > "$ND/docker-compose.yml"
    ( SCRIPT_DIR="$ND"; COMPOSE_PROJECT_NAME="$P"; _ensure_pentest_net >/dev/null 2>&1 )
    labels="$(docker network inspect "${P}_pentest-net" -f '{{index .Labels "com.docker.compose.project"}} {{index .Labels "com.docker.compose.network"}} {{range .IPAM.Config}}{{.Subnet}}{{end}}' 2>/dev/null)"
    assert_eq "a fresh project's network exists with compose's labels and subnet" "$labels" "$P pentest-net 10.213.93.0/28"
    if docker image inspect busybox >/dev/null 2>&1; then
        up="$(cd "$ND" && env -u COMPOSE_FILE -u COMPOSE_PROFILES docker compose -p "$P" --env-file /dev/null \
              --profile capture up --no-start 2>&1)"; rc=$?
        if [[ $rc -eq 0 && "$up" != *"incorrect label"* && "$up" != *"Network ${P}_pentest-net Created"* ]]; then
            pass "compose adopts it for the capture-profile service (no new network, no label complaint)"
        else
            fail "compose adopts it for the capture-profile service (rc $rc: $(tr '\n' ' ' <<< "$up" | cut -c1-200))"
        fi
        (cd "$ND" && env -u COMPOSE_FILE -u COMPOSE_PROFILES docker compose -p "$P" --env-file /dev/null \
            --profile capture down >/dev/null 2>&1) || true
    else
        printf '  SKIP compose adoption (no local busybox image; the network check above still ran)\n'
    fi
    docker network rm "${P}_pentest-net" >/dev/null 2>&1 || true
    rm -rf "$ND"
else
    CANNOT="no docker daemon (the pentest network check)"
fi
docker() {
    printf 'docker %s\n' "$*" >> "$CALLS"
    if [[ "$1 ${2:-}" == "container inspect" ]]; then
        [[ "$SHARED_EXISTS" == 1 && "${*: -1}" == "redamon-kali" ]] || return 1
        printf '/redamon-kali %s\n' "$SHARED_PROJECT"
    fi
    return 0
}

# =============================================================================
section "the update map"
map() {  # map <changed files...>: prints "core=..|restart=..|tools=.."
    local rebuild_core=() restart_only=() rebuild_tools=() rebuild_capture=false rebuild_plugins=false
    _map_core_changes "$(printf '%s\n' "$@")"
    _map_tool_changes "$(printf '%s\n' "$@")"
    printf 'core=%s|restart=%s|tools=%s' "${rebuild_core[*]-}" "${restart_only[*]-}" "${rebuild_tools[*]-}"
}
assert_eq "mcp/kali-sandbox/ rebuilds the tool image only" "$(map mcp/kali-sandbox/entrypoint.sh)" "core=|restart=|tools=kali-sandbox"
assert_eq "mcp/requirements.txt rebuilds the tool image only" "$(map mcp/requirements.txt)" "core=|restart=|tools=kali-sandbox"
assert_eq "mcp/servers/ rebuilds and restarts nothing (sandboxes drain onto it, TD-28)" \
    "$(map mcp/servers/nuclei_server.py mcp/servers/tunnel_manager.py)" "core=|restart=|tools="

# =============================================================================
# The real cmd_update, stubbed around it.
W="$TMP/update"; mkdir -p "$W"
export W REPO_ROOT
cat > "$W/stubs.sh" <<'STUBS'
# shellcheck disable=SC1091
source "$REPO_ROOT/redamon.sh"
set +e
SCRIPT_DIR="$W"
UPDATE_PENDING_FILE="$W/.update-pending"
LOG="$W/calls.log"
record() { echo "$*" >> "$LOG"; }
info()    { echo "INFO $*"; }
success() { echo "OK $*"; }
warn()    { echo "WARN $*"; }
error()   { echo "ERROR $*"; }
print_banner() { :; }
for fn in _assert_checkout_writable _warn_root_owned_runtime_files _migrate_reorg_layout \
          _migrate_legacy_kbase_flag _kb_export_env _gpu_export_env _gpu_compose_overlay \
          check_prerequisites require_plugin_engine _restore_runtime_tracked_files \
          preflight_ram_gate export_version ensure_auth_secrets ensure_wiki_checkout \
          mcp_server_preflight ensure_volume_ownership ensure_db_secrets ensure_gvm_secret \
          ensure_osv_db ensure_sca_intel _map_plugin_consumers _update_resume_hint \
          export_resource_caps reconcile_gvm_admin_password verify_core_running \
          _confirm_root _urlscan_backfill_once _old_page_cache_volume_remove_once; do
    eval "$fn() { :; }"
done
preflight_disk_gate() { record "DISK_GATE $1"; return "${STUB_DISK_RC:-0}"; }
_plugins_build_runner() { record "PLUGINS_BUILD"; }
_plugins_prepare() { record "PLUGINS_PREPARE"; }
_update_preview() { record "PREVIEW"; return "${STUB_PREVIEW_RC:-0}"; }
_update_pending_base() { :; }
ensure_admin() { record "ENSURE_ADMIN"; }
is_gvm_enabled() { return 1; }
get_version() { echo "9.9.9"; }
PULLED=false
_update_pull() { record "PULL"; [[ "${STUB_PULL_MOVES:-false}" == true ]] && PULLED=true; return 0; }
git() {
    case "$*" in
        *"rev-parse HEAD"*) if [[ "$PULLED" == true || -n "${REDAMON_UPDATE_FROM:-}" ]]; then echo newhead; else echo oldhead; fi ;;
        *"diff --name-only"*) printf '%s\n' ${STUB_CHANGED:-docker-compose.yml} ;;
    esac
    return 0
}
exec() { record "EXEC $*"; exit 0; }
_service_running() { [[ " ${STUB_RUNNING:-postgres webapp agent} " == *" $1 "* ]]; }
docker() {
    record "docker $*"
    case "$1 ${2:-}" in
        "container inspect")
            [[ "${STUB_SHARED:-1}" == 1 && "${*: -1}" == redamon-kali ]] || return 1
            echo "/redamon-kali ${STUB_SHARED_PROJECT:-updproj}" ;;
        "image inspect")
            if [[ "$*" == *redamon-kali-sandbox:latest* ]]; then
                [[ "${STUB_KALI_IMAGE:-1}" == 1 ]] || return 1
                [[ "$*" == *msf_refresh* ]] && printf '%s\n' "${STUB_MSF_LABEL-}"
            fi ;;
    esac
    return 0
}
compose_build() { record "compose_build $* STAMP=${MSF_REFRESH_STAMP:-}"; [[ "$*" == *"build kali-sandbox"* ]] && return "${STUB_MSF_BUILD_RC:-0}"; return 0; }
_converge_running_core()        { record "RESTART converge"; }
plugins_converge()              { record "RESTART plugins_converge"; }
_reconcile_capture_if_running() { record "RESTART capture_refresh"; }
ensure_capture_proxy_running()  { record "RESTART capture_start"; }
STUBS

TODAY="$(date -u +%Y%m%d)"
run_update() {  # run_update <cmd_update args...>; RC and OUT set
    : > "$W/calls.log"; rm -f "$W/.update-pending" "$W/.env"
    OUT="$( (
        # shellcheck disable=SC1091
        source "$W/stubs.sh"; set -euo pipefail
        REDAMON_UPDATE_FROM=oldhead cmd_update "$@"
    ) 2>&1 </dev/null)"; RC=$?
}
calls() { cat "$W/calls.log"; }
line_of() { grep -nE -- "$1" "$W/calls.log" | head -n1 | cut -d: -f1; }
RM='^docker rm -f redamon-kali$'
MSF="^compose_build --profile tools build kali-sandbox STAMP="

export COMPOSE_PROJECT_NAME=updproj
export STUB_SHARED=1 STUB_KALI_IMAGE=1 STUB_MSF_LABEL=20000101 STUB_CHANGED=docker-compose.yml \
       STUB_DISK_RC=0 STUB_PREVIEW_RC=0 STUB_MSF_BUILD_RC=0 STUB_RUNNING="postgres webapp agent"

section "update retires the shared container only after every build"
run_update
assert_eq "the update exits 0" "$RC" "0"
assert_eq "the shared container is removed once" "$(grep -cE "$RM" "$W/calls.log")" "1"
ascending "after the core and plugin builds and the preview, before the recreate" \
    "$(line_of '^compose_build build ')" "$(line_of '^PLUGINS_BUILD$')" "$(line_of '^PREVIEW$')" \
    "$(line_of "$RM")" "$(line_of '^docker compose up -d')"
STUB_KALI_IMAGE=0 run_update
ascending "and after the tool build" "$(line_of '^compose_build --profile tools build')" "$(line_of "$RM")"
assert_not_contains "the recreate names no Kali service" "$(grep '^docker compose up' "$W/calls.log")" "kali"
STUB_CHANGED=webapp/src/app/page.tsx run_update
ascending "the targeted branch too: after the webapp build, before its restart" \
    "$(line_of '^compose_build build webapp')" "$(line_of "$RM")" "$(line_of '^docker compose up -d --no-deps webapp')"
STUB_SHARED=0 run_update
assert_eq "no shared container: no docker rm" "$(grep -c '^docker rm' "$W/calls.log")" "0"

run_update --preview
assert_eq "update --preview exits 0" "$RC" "0"
assert_eq "update --preview leaves redamon-kali alone" "$(grep -cE "$RM" "$W/calls.log")" "0"
STUB_PREVIEW_RC=1 run_update
assert_eq "the operator's no stops the update" "$RC" "1"
assert_eq "and leaves redamon-kali alone" "$(grep -cE "$RM" "$W/calls.log")" "0"
STUB_DISK_RC=1 run_update
assert_eq "the disk gate stops the update" "$RC" "1"
assert_eq "and leaves redamon-kali alone" "$(grep -cE "$RM" "$W/calls.log")" "0"
assert_eq "and builds nothing" "$(grep -c '^compose_build' "$W/calls.log")" "0"

section "update: the Kali image's rules"
STUB_CHANGED=mcp/kali-sandbox/Dockerfile run_update
assert_contains "a change under mcp/kali-sandbox/ builds the tool image" "$(calls)" "compose_build --profile tools build kali-sandbox STAMP="
assert_not_contains "never as a core service" "$(calls)" "compose_build build kali-sandbox"
STUB_MSF_LABEL="$TODAY" STUB_CHANGED=mcp/servers/nuclei_server.py run_update
assert_eq "mcp/servers/ only: nothing is built" "$(grep -c '^compose_build' "$W/calls.log")" "0"
assert_eq "and nothing is restarted" "$(grep -c '^docker compose up' "$W/calls.log")" "0"
STUB_KALI_IMAGE=0 STUB_CHANGED=webapp/src/app/page.tsx run_update
assert_contains "a missing Kali image is built with the tool images" "$(grep '^compose_build --profile tools build' "$W/calls.log" | head -n1)" "kali-sandbox"
assert_contains "and that raises the full-build disk gate" "$(calls)" "DISK_GATE $DISK_FULL_BUILD_GB"

section "update: the daily Metasploit refresh"
STUB_CHANGED=webapp/src/app/page.tsx run_update
assert_eq "an older label: one refresh build" "$(grep -cE "$MSF" "$W/calls.log")" "1"
assert_contains "with today's stamp, for that command only" "$(grep -E "$MSF" "$W/calls.log")" "STAMP=$TODAY"
ascending "after the core converged, before ensure_admin" \
    "$(line_of '^docker compose up -d --no-deps webapp')" "$(line_of "$MSF")" "$(line_of '^ENSURE_ADMIN$')"
assert_eq "no other build carries the stamp" "$(grep '^compose_build' "$W/calls.log" | grep -vE "$MSF" | grep -c 'STAMP=[^ ]')" "0"
assert_eq "the stamp is never written to .env" "$(grep -c MSF_REFRESH_STAMP "$W/.env" 2>/dev/null || echo 0)" "0"
STUB_MSF_LABEL="$TODAY" STUB_CHANGED=webapp/src/app/page.tsx run_update
assert_eq "today's label: no refresh build" "$(grep -cE "$MSF" "$W/calls.log")" "0"
STUB_MSF_LABEL="" STUB_CHANGED=webapp/src/app/page.tsx run_update
assert_eq "an image never refreshed (empty label): one refresh build" "$(grep -cE "$MSF" "$W/calls.log")" "1"
MSF_REFRESH_STAMP=19990101 STUB_CHANGED=webapp/src/app/page.tsx run_update
assert_contains "a stamp in the environment is not used" "$(grep -E "$MSF" "$W/calls.log")" "STAMP=$TODAY"
STUB_MSF_LABEL="\$(touch $W/pwned)" STUB_CHANGED=webapp/src/app/page.tsx run_update
if [[ -e "$W/pwned" ]]; then fail "the image label is never evaluated"; else pass "the image label is never evaluated"; fi
STUB_MSF_BUILD_RC=1 STUB_CHANGED=webapp/src/app/page.tsx run_update
assert_eq "a failed refresh build does not fail the update" "$RC" "0"
assert_contains "it warns" "$OUT" "WARN"
assert_contains "and the update goes on" "$(calls)" "ENSURE_ADMIN"
STUB_CHANGED=README.md run_update
assert_eq "a refresh alone never raises the full-build disk gate" "$(grep -c "^DISK_GATE $DISK_FULL_BUILD_GB" "$W/calls.log")" "0"
assert_eq "but it still runs" "$(grep -cE "$MSF" "$W/calls.log")" "1"
dispatch="$(sed -n '/^if \[\[ "\${BASH_SOURCE\[0\]}" == "\${0}" \]\]; then$/,$p' "$REPO_ROOT/redamon.sh")"
ascending "every other build gets an empty stamp, whatever .env or the caller says" \
    "$(grep -nxF 'export MSF_REFRESH_STAMP=""' <<< "$dispatch" | head -n1 | cut -d: -f1)" \
    "$(grep -nF 'case "${1:-help}" in' <<< "$dispatch" | head -n1 | cut -d: -f1)"
run_update --preview
assert_eq "not in --preview" "$(grep -cE "$MSF" "$W/calls.log")" "0"
: > "$W/calls.log"
OUT="$( (source "$W/stubs.sh"; set -euo pipefail; unset REDAMON_UPDATE_FROM; STUB_PULL_MOVES=false cmd_update) 2>&1 </dev/null)"
assert_contains "nothing to pull: the update says so" "$OUT" "Already up to date"
assert_eq "and refreshes nothing" "$(grep -cE "$MSF" "$W/calls.log")" "0"
assert_eq "and still retires the shared container" "$(grep -cE "$RM" "$W/calls.log")" "1"
: > "$W/calls.log"
OUT="$( (source "$W/stubs.sh"; set -euo pipefail; unset REDAMON_UPDATE_FROM; STUB_RUNNING="" STUB_PULL_MOVES=false cmd_update) 2>&1 </dev/null)"
assert_eq "even with the stack down" "$(grep -cE "$RM" "$W/calls.log")" "1"
: > "$W/calls.log"
OUT="$( (source "$W/stubs.sh"; set -euo pipefail; unset REDAMON_UPDATE_FROM; STUB_SHARED_PROJECT=other STUB_PULL_MOVES=false cmd_update) 2>&1 </dev/null)"
assert_eq "but never another compose project's" "$(grep -cE "$RM" "$W/calls.log")" "0"
: > "$W/calls.log"
OUT="$( (source "$W/stubs.sh"; set -euo pipefail; unset REDAMON_UPDATE_FROM; STUB_PULL_MOVES=false cmd_update --preview) 2>&1 </dev/null)"
assert_eq "nothing to pull with --preview: left alone" "$(grep -cE "$RM" "$W/calls.log")" "0"

# =============================================================================
section "the deploy refuses a port pool that covers a port the host already serves"
# revshell-open forwards every pool port from the public address to 127.0.0.1, so a
# pool over a loopback-only service would publish that service past nginx.
DSH_DIR="$REPO_ROOT/tooling/deploy/single-host"
FIXTURE=".env.s21pooltest$$"
pool_verdict() {  # <pool> [extra fixture line] [checkout root to read the compose files from] -> ok | refused
    printf 'ACCESS_MODE=https-ip\nTLS_MODE=self-signed\nOPERATOR_ALLOW_CIDRS=198.51.100.0/24\nKALI_SANDBOX_PORT_POOL=%s\n%s\n' \
        "$1" "${2:-}" > "$DSH_DIR/$FIXTURE"
    ( cd "$DSH_DIR" && PLANTED_ROOT="${3:-}" bash -c '
        set -uo pipefail
        source ./deploy.sh status 203.0.113.5 /dev/null ubuntu --env "'"${FIXTURE#.env.}"'" >/dev/null 2>&1 || exit 3
        [ -n "$PLANTED_ROOT" ] && SCRIPT_DIR="$PLANTED_ROOT/tooling/deploy/single-host"
        ( preflight_validate ) >/dev/null 2>&1 && echo ok || echo refused' 2>/dev/null )
    rm -f "$DSH_DIR/$FIXTURE"
}
if [[ "$(pool_verdict 4500-4509)" == ok ]]; then
    pass "a pool of free ports is accepted"
    assert_eq "on 127.0.0.1 too" "$(pool_verdict 127.0.0.1:4500-4509)" "ok"
    assert_eq "any other bind address is refused" "$(pool_verdict 0.0.0.0:4500-4509)" "refused"
    assert_eq "a malformed pool is refused" "$(pool_verdict 4509-4500)" "refused"
    for p in 22 443 3000 4444 5432 7474 7687 8010 8090 8888 11434; do
        assert_eq "a pool over $p is refused" "$(pool_verdict "$p-$p")" "refused"
    done
    assert_eq "a wide pool over the services is refused" "$(pool_verdict 5000-9000)" "refused"
    assert_eq "a port moved by the operator follows (WEBAPP_PORT=3100)" "$(pool_verdict 3100-3100 WEBAPP_PORT=3100)" "refused"
    # The deploy forwards no *_PORT knob to the server, which may keep the default.
    assert_eq "and the default stays refused" "$(pool_verdict 3000-3000 WEBAPP_PORT=3100)" "refused"
    assert_eq "AGENT_PORT=9090: 9090 refused" "$(pool_verdict 9090-9090 AGENT_PORT=9090)" "refused"
    assert_eq "AGENT_PORT=9090: 8090 still refused" "$(pool_verdict 8090-8090 AGENT_PORT=9090)" "refused"
    assert_eq "a pool below 1024 is refused" "$(pool_verdict 1000-1010)" "refused"
    assert_eq "from 1024 it is not" "$(pool_verdict 1024-1030)" "ok"
    assert_eq "100 ports are accepted" "$(pool_verdict 4500-4599)" "ok"
    assert_eq "more (one forwarder unit each) are refused" "$(pool_verdict 4500-4600)" "refused"
    # A publish the parser cannot read makes the pool unprovable: refused.
    PR="$(mktemp -d "$REPO_ROOT/.s21-ports.XXXXXX")"
    mkdir -p "$PR/tooling/deploy/single-host/compose"
    cp "$REPO_ROOT"/docker-compose*.yml "$PR/"
    cp "$DSH_DIR/compose/docker-compose.prod.yml" "$PR/tooling/deploy/single-host/compose/"
    assert_eq "the copied compose files: the free pool is still accepted" "$(pool_verdict 4500-4509 '' "$PR")" "ok"
    for planted in '      - target: 4501\n        published: 4501' '      - "4500-4505:4500-4505"' '      - "[::1]:4502:4502"' '      - "4503"'; do
        cp "$REPO_ROOT/docker-compose.yml" "$PR/docker-compose.yml"
        printf '  s21-planted:\n    image: busybox\n    ports:\n%b\n' "$planted" >> "$PR/docker-compose.yml"
        assert_eq "an unreadable publish ($(head -n1 <<< "$(printf '%b' "$planted")" | xargs)) refuses the pool" "$(pool_verdict 4500-4509 '' "$PR")" "refused"
    done
    rm -rf "$PR"
else
    fail "deploy.sh could not be sourced headlessly, or refused a free pool"
fi
rm -f "$DSH_DIR/$FIXTURE"
assert_contains "verify names the fix for a leftover 4444 forwarder" \
    "$(sed -n '/^verify() {/,/^}/p' "$DSH_DIR/deploy.sh")" "4444 is the reverse-shell forwarder of a host opened before"

# =============================================================================
section "the deploy overlay of the previous release renders against this base"
if docker_bin="$(type -P docker)" && "$docker_bin" compose version >/dev/null 2>&1; then
    # /dev/null for the env file: the checkout's own .env never takes part, and a
    # snap-packaged docker cannot see this script's private /tmp.
    render() {  # render <label> <compose args...>
        local label="$1" err; shift
        if err="$(cd "$REPO_ROOT" && env -u COMPOSE_FILE -u COMPOSE_PROFILES \
                NEO4J_PASSWORD=x POSTGRES_PASSWORD=x \
                "$docker_bin" compose --env-file /dev/null "$@" config -q 2>&1)"; then
            pass "$label"
        else
            fail "$label: $(head -n 3 <<< "$err")"
        fi
    }
    render "the base" -f docker-compose.yml
    render "the base, tools profile" -f docker-compose.yml --profile tools
    render "the base + this release's overlay" -f docker-compose.yml -f tooling/deploy/single-host/compose/docker-compose.prod.yml
    render "the base + the v7.9.0 overlay" -f docker-compose.yml -f tests/fixtures/deploy_overlay_v7.9.0/docker-compose.prod.yml
    render "the base + the v7.9.0 overlay, tools profile" --profile tools -f docker-compose.yml -f tests/fixtures/deploy_overlay_v7.9.0/docker-compose.prod.yml
    svcs="$(cd "$REPO_ROOT" && env -u COMPOSE_FILE -u COMPOSE_PROFILES NEO4J_PASSWORD=x POSTGRES_PASSWORD=x \
            "$docker_bin" compose --env-file /dev/null -f docker-compose.yml \
            -f tests/fixtures/deploy_overlay_v7.9.0/docker-compose.prod.yml config --services 2>/dev/null)"
    assert_not_contains "with the old overlay, a plain up still starts no Kali service" " $(tr '\n' ' ' <<< "$svcs") " " kali-sandbox "
else
    CANNOT="docker compose is not available (the overlay render)"
fi

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
[[ -z "$CANNOT" ]] || { echo "CANNOT RUN: $CANNOT"; exit 77; }
exit 0
