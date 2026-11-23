#!/usr/bin/env bash
# =============================================================================
# `./redamon.sh update` rebuilds every image whose baked files changed.
#
# The changed-file -> service map (_map_core_changes, _map_tool_changes and
# _map_baked_graph_db) is the only thing that decides whether an update rebuilds
# a service. A path it does not cover is updated on disk and silently NOT in the
# running container: mcp/requirements.txt and kali's other baked files, and
# recon_settings/ in the recon image, were such paths (drift-map #7).
#
# So the expectations are DERIVED, not typed here: every COPY/ADD source of every
# service docker-compose.yml builds (and its Dockerfile) must make the map rebuild
# that service's image, or at least restart the service when a compose bind mount
# shadows the baked copy. A hand list of expected rules is what let the map's
# mistakes pass before (drift-map #30). What no Dockerfile can express, a
# long-running service caching Python modules it imports from its bind mounts,
# is derived too: every module recon-orchestrator or traffic-ingest imports from
# a bind (followed through what those modules import at load time) must restart
# the service (drift-map #91).
#
# Hermetic: sources redamon.sh and reads the tracked files, no Docker. Needs
# python3 with PyYAML and git; without them it exits 77, which the gate counts as
# a suite that cannot run. Run:
#   bash tests/redamon_update_map_test.sh
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass; else fail "$1 (got='$2' expected='$3')"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

if ! command -v python3 >/dev/null 2>&1 || ! python3 -c 'import yaml' 2>/dev/null \
    || ! git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    echo "  CANNOT RUN  needs python3 with PyYAML and a git checkout"
    exit 77
fi

# Images whose sources the ORCHESTRATOR mounts into each container it spawns, so a
# source change reaches the next scan or sandbox without a rebuild; only the
# Dockerfile and requirements are baked for real. A scan's binds are in
# recon_orchestrator/container_manager.py; a Kali sandbox's in the contract's mount
# plan (recon_orchestrator/sandbox_contract.py), and a sandbox started on older
# mcp/servers code drains onto a new one by itself (TD-28).
# "<service> <repo path prefix> <container path it is bound at>"
SPAWN_MOUNTED=(
    "ai-attack-surface scanners/ai_attack_surface_scan/ /app/ai_attack_surface_scan"
    "supply-chain scanners/supply_chain_scan/ /app/supply_chain_scan"
    "kali-sandbox mcp/servers/ /opt/mcp_servers"
)

# everything one changed file makes `update` do: "<built services> | <restarted>"
effect() {
    local rebuild_core=() restart_only=() rebuild_tools=()
    local rebuild_capture=false rebuild_plugins=false
    _map_core_changes "$1"
    _map_tool_changes "$1"
    [[ "$rebuild_capture" == "true" ]] && rebuild_tools+=(capture-proxy traffic-ingest)
    [[ "$rebuild_plugins" == "true" ]] && rebuild_tools+=(plugin-runner plugin-gateway)
    echo " ${rebuild_core[*]-} ${rebuild_tools[*]-} | ${restart_only[*]-} "
}

section "every file an image bakes rebuilds it"
read -r -d '' PY <<'PYEOF'
import fnmatch, json, os, re, subprocess, sys
import yaml

root = sys.argv[1]
doc = yaml.safe_load(open(os.path.join(root, "docker-compose.yml")))
project = doc.get("name") or os.path.basename(root).lower()
tracked = [f for f in subprocess.run(["git", "-C", root, "ls-files"], capture_output=True,
                                     text=True, check=True).stdout.split("\n") if f]
BUILD_NAMES = re.compile(r"(Dockerfile|requirements[^/]*|constraints[^/]*|entrypoint[^/]*|package(-lock)?\.json)$")


def sample(paths):
    """Every build-relevant file name, plus one file per directory down to three
    levels: the update map's rules are path prefixes no deeper than that and a few
    file names, so this probes every rule without probing every file."""
    seen, out = set(), []
    for f in sorted(paths):
        key = "/".join(os.path.dirname(f).split("/")[:3])
        if BUILD_NAMES.search(f) or key not in seen:
            out.append(f)
            seen.add(key)
    return out


for svc, spec in doc["services"].items():
    build = spec.get("build")
    if not build:
        continue
    ctx, df = (build, "Dockerfile") if isinstance(build, str) else (build.get("context", "."), build.get("dockerfile", "Dockerfile"))
    ctx = os.path.normpath(ctx)
    image = (spec.get("image") or f"{project}-{svc}").split(":")[0]
    print(f"IMAGE\t{svc}\t{image}")
    for arg in (build.get("args") or {}) if isinstance(build, dict) else ():
        print(f"ARG\t{svc}\t{arg}")
    dockerfile = os.path.normpath(os.path.join(ctx, df))
    sources = {dockerfile}
    text = re.sub(r"\\\n", " ", open(os.path.join(root, dockerfile), encoding="utf-8").read())
    for line in text.splitlines():
        m = re.match(r"\s*(COPY|ADD)\s+(.+)", line, re.I)
        if not m or "--from" in m.group(2):
            continue
        args = m.group(2).strip()
        parts = json.loads(args) if args.startswith("[") else [a for a in args.split() if not a.startswith("--")]
        for src in parts[:-1]:
            sources.add(os.path.normpath(os.path.join(ctx, src)))
    named, under_dirs = set(), set()
    for src in sources:
        for f in tracked:
            if f == src or fnmatch.fnmatch(f, src):
                named.add(f)
            elif src == "." or f.startswith(src + "/"):
                under_dirs.add(f)
    for f in sorted(named | set(sample(under_dirs - named))):
        print(f"COPY\t{svc}\t{f}")
    for vol in spec.get("volumes") or []:
        host = vol.split(":")[0] if isinstance(vol, str) else vol.get("source", "")
        if host.startswith("./"):
            print(f"BIND\t{svc}\t{os.path.normpath(host)}")
PYEOF
listing="$(python3 -c "$PY" "$REPO_ROOT")" || { fail "could not read the compose build graph"; listing=""; }

declare -A image_of=()
binds=()
copies=()
build_args=()
while IFS=$'\t' read -r kind svc path; do
    case "$kind" in
        IMAGE) image_of[$svc]="$path" ;;
        BIND)  binds+=("$svc $path") ;;
        COPY)  copies+=("$svc $path") ;;
        ARG)   build_args+=("$svc $path") ;;
    esac
done <<< "$listing"

assert_eq "the compose file builds at least the core and tool images" \
    "$([[ ${#image_of[@]} -ge 15 && ${#copies[@]} -ge 100 ]] && echo yes)" "yes"

shadowed_by_bind() {   # <service> <file>
    local b
    for b in "${binds[@]}"; do
        [[ "${b%% *}" == "$1" ]] || continue
        [[ "$2" == "${b#* }" || "$2" == "${b#* }/"* ]] && return 0
    done
    return 1
}

spawn_mounted() {      # <service> <file>
    local m
    [[ "$(basename "$2")" =~ ^(Dockerfile|.*requirements.*)$ ]] && return 1
    local svc prefix _bind
    for m in "${SPAWN_MOUNTED[@]}"; do
        read -r svc prefix _bind <<< "$m"
        [[ "$svc" == "$1" && "$2" == "$prefix"* ]] && return 0
    done
    return 1
}

for entry in "${copies[@]}"; do
    svc="${entry%% *}" file="${entry#* }"
    out="$(effect "$file")"
    built="${out%%|*}" restarted="${out#*|}"
    rebuilt=false
    for other in $built; do
        [[ "${image_of[$other]-}" == "${image_of[$svc]}" ]] && rebuilt=true
    done
    if [[ "$rebuilt" == "true" ]]; then
        pass
    elif shadowed_by_bind "$svc" "$file" && [[ "$restarted" == *" $svc "* ]]; then
        pass
    elif spawn_mounted "$svc" "$file"; then
        pass
    else
        fail "$svc bakes $file, but a release changing it does not rebuild $svc (built:$built restarted:$restarted)"
    fi
done

for m in "${SPAWN_MOUNTED[@]}"; do
    read -r svc prefix bind <<< "$m"
    if [[ "$svc" == kali-sandbox ]]; then
        # The servers base is the orchestrator's own read-only mount of mcp/servers,
        # bound into every sandbox at SERVERS_TARGET by the mount plan.
        contract="$REPO_ROOT/recon_orchestrator/sandbox_contract.py"
        bound="$(grep -cxF "SERVERS_TARGET = \"$bind\"" "$contract")/$(grep -cF 'MountTarget(MOUNT_SERVERS, "", SERVERS_TARGET, True)' "$contract")/$(grep -cE "^      - \./${prefix%/}:/app/mcp-servers:ro$" "$REPO_ROOT/docker-compose.yml")"
        assert_eq "the sandbox mount plan binds ${prefix%/} at $bind (contract/mount/compose)" "$bound" "1/1/1"
        continue
    fi
    assert_eq "container_manager.py binds ${prefix%/} at $bind" \
        "$(grep -cF "{\"bind\": \"$bind\", \"mode\"" "$REPO_ROOT/recon_orchestrator/container_manager.py" | awk '{print ($1 > 0) ? "yes" : "no"}')" "yes"
done

section "graph_db/ goes only to the images that bake it"
tools() {
    local rebuild_tools=()
    [[ -n "${2-}" ]] && read -ra rebuild_tools <<< "$2"
    _map_baked_graph_db "$1"
    echo "tools=${rebuild_tools[*]-}"
}
assert_eq "the supply-chain images mount graph_db rather than bake it" \
    "$(tools 'graph_db/mixins/base_mixin.py')" "tools=recon vuln-scanner github-secret-hunter"
assert_eq "an image the release already rebuilds is not queued twice" \
    "$(tools 'graph_db/mixins/base_mixin.py' 'recon vuln-scanner')" "tools=recon vuln-scanner github-secret-hunter"
assert_eq "without a graph_db/ change nothing is added" \
    "$(tools $'recon/main.py\nagentic/api.py' 'wcvs')" "tools=wcvs"

section "a long-running service reloads every module it imports from a bind mount"
# Every module the service's own code imports (any import, a lazy one included,
# since it is cached once it ran), resolved against its WORKDIR and its compose
# bind mounts, then every module THOSE import at load time. A bind-mounted
# module is updated on disk by the release and stays cached in the running
# process, so each one must make `update` restart (or rebuild) the service.
read -r -d '' IMPORTS_PY <<'PYEOF'
import ast, os, re, subprocess, sys
import yaml

root = sys.argv[1]
extra_roots = {}
for spec in sys.argv[2:]:
    svc, path = spec.split(" ", 1)
    extra_roots.setdefault(svc, []).append(path)
doc = yaml.safe_load(open(os.path.join(root, "docker-compose.yml")))
tracked = set(subprocess.run(["git", "-C", root, "ls-files"], capture_output=True,
                             text=True, check=True).stdout.split("\n")) - {""}
dirs = {os.path.dirname(f) for f in tracked}
dirs |= {d.rsplit("/", i)[0] for d in list(dirs) for i in range(d.count("/") + 1)}


def is_test(path):
    parts = path.split("/")
    return "tests" in parts or parts[-1].startswith("test_") or parts[-1] == "conftest.py"


def imports(tree, load_time_only):
    """(level, module, names) of every import; with load_time_only, skip function
    bodies, which run only when called."""
    out = []
    def visit(node):
        for child in ast.iter_child_nodes(node):
            if load_time_only and isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
                continue
            if isinstance(child, ast.Import):
                out.extend((0, a.name, []) for a in child.names)
            elif isinstance(child, ast.ImportFrom):
                out.append((child.level, child.module, [a.name for a in child.names]))
            visit(child)
    visit(tree)
    return out


for svc in ("recon-orchestrator", "traffic-ingest"):
    spec = doc["services"][svc]
    build = spec["build"]
    ctx, df = (build, "Dockerfile") if isinstance(build, str) else (build.get("context", "."), build.get("dockerfile", "Dockerfile"))
    dockerfile = os.path.normpath(os.path.join(ctx, df))
    workdirs = re.findall(r"^\s*WORKDIR\s+(\S+)", open(os.path.join(root, dockerfile)).read(), re.M)
    workdir = workdirs[-1].rstrip("/") if workdirs else "/"
    binds = {}
    for vol in spec.get("volumes") or []:
        host, _, rest = vol.partition(":") if isinstance(vol, str) else (vol.get("source", ""), "", vol.get("target", ""))
        target = rest.split(":")[0].rstrip("/")
        if host.startswith("./") and target:
            binds[target] = os.path.normpath(host)
    own = binds.get(workdir) or os.path.dirname(dockerfile)
    mounts = dict(binds)
    mounts.setdefault(workdir, own)
    roots = extra_roots.get(svc, []) + [workdir]   # sys.path.insert(0, ...) goes first
    for r in extra_roots.get(svc, []):
        if r not in binds:
            print(f"STALE\t{svc}\t{r}")

    def host_of(cpath):
        best = max((k for k in mounts if cpath == k or cpath.startswith(k + "/")), key=len, default=None)
        return None if best is None else os.path.normpath(mounts[best] + cpath[len(best):])

    def resolve(modname):
        """[(module name, file)] that importing modname runs, or None."""
        parts = modname.split(".")
        for r in roots:
            run, base = [], r
            for i, p in enumerate(parts):
                name = ".".join(parts[: i + 1])
                h = host_of(f"{base}/{p}")
                last = i == len(parts) - 1
                if h and h in dirs:
                    if f"{h}/__init__.py" in tracked:
                        run.append((name, f"{h}/__init__.py"))
                    if last:
                        return run
                    base = f"{base}/{p}"
                elif last and h and f"{h}.py" in tracked:
                    return run + [(name, f"{h}.py")]
                else:
                    break
        return None

    def targets(level, module, names, modname, file):
        if level:
            pkg = modname if file.endswith("/__init__.py") else modname.rpartition(".")[0]
            pkg = ".".join(pkg.split(".")[: len(pkg.split(".")) - (level - 1)])
            module = f"{pkg}.{module}" if module else pkg
        yield module
        for n in names:
            yield f"{module}.{n}"

    def scan(name, f, load_time_only, via, queue):
        for level, module, names in imports(ast.parse(open(os.path.join(root, f)).read()), load_time_only):
            for target in targets(level, module, names, name, f):
                queue.extend((n, hit, via) for n, hit in resolve(target) or ())

    queue = []
    for f in sorted(f for f in tracked if f.startswith(own + "/") and f.endswith(".py") and not is_test(f)):
        name = f[len(own) + 1:-3].replace("/", ".")
        scan(name[: -len(".__init__")] if name.endswith(".__init__") else name, f, False, f, queue)
    seen = set()
    while queue:
        name, f, via = queue.pop()
        if f.startswith(own + "/") or f in seen:
            continue
        seen.add(f)
        print(f"CACHED\t{svc}\t{f}\t{via}")
        scan(name, f, True, via, queue)
PYEOF

# The one input the scan cannot see: /defaults puts /app/recon on sys.path at run
# time (recon_orchestrator/api.py) and imports project_settings and
# settings_registry bare from it, so that directory is an import root too.
EXTRA_IMPORT_ROOTS=("recon-orchestrator /app/recon")
assert_eq "api.py still puts /app/recon on sys.path (else drop it from EXTRA_IMPORT_ROOTS)" \
    "$(grep -q 'Path("/app/recon")' "$REPO_ROOT/recon_orchestrator/api.py" \
        && grep -q 'sys.path.insert(0, str(recon_path))' "$REPO_ROOT/recon_orchestrator/api.py" && echo yes)" "yes"

# The capture pair is spawned by the orchestrator, not compose, so no map rule
# restarts traffic-ingest: cmd_update's last _reconcile_capture_if_running
# recreates a running pair on every update. `declare -f` prints the function one
# top-level command per line at four spaces, so this is that call, unconditional
# and after the restart loop.
late_reconcile="$(declare -f cmd_update | awk '/--force-recreate "\$svc"/{seen=1} seen && /^    _reconcile_capture_if_running;?$/{print "yes"; exit}')"
assert_eq "cmd_update recreates a running capture pair on every update, after the restarts" \
    "$late_reconcile" "yes"

imports_listing="$(python3 -c "$IMPORTS_PY" "$REPO_ROOT" "${EXTRA_IMPORT_ROOTS[@]}")" \
    || { fail "could not scan the services' imports"; imports_listing=""; }
declare -A cached_count=()
cached_files=""
while IFS=$'\t' read -r kind svc file via; do
    [[ -n "$kind" ]] || continue
    if [[ "$kind" == "STALE" ]]; then
        fail "EXTRA_IMPORT_ROOTS names $file for $svc, which compose does not bind-mount"
        continue
    fi
    cached_count[$svc]=$(( ${cached_count[$svc]:-0} + 1 ))
    cached_files+="$svc $file"$'\n'
    out="$(effect "$file")"
    built="${out%%|*}" restarted="${out#*|}"
    [[ "$late_reconcile" == "yes" ]] && restarted+=" capture-proxy traffic-ingest "
    rebuilt=false
    for other in $built; do
        [[ "${image_of[$other]-}" == "${image_of[$svc]-}" ]] && rebuilt=true
    done
    if [[ "$rebuilt" == "true" || "$restarted" == *" $svc "* ]]; then
        pass
    else
        fail "$svc imports $file from a bind mount (via $via), but a release changing it neither restarts nor rebuilds $svc (built:$built restarted:$restarted)"
    fi
done <<< "$imports_listing"

# Witnesses that the scan still sees through the import shims, so an empty result
# cannot pass as "nothing to restart".
assert_eq "the scan follows trufflehog_registry.py into the TruffleHog registry" \
    "$(grep -cx 'recon-orchestrator scanners/trufflehog_scan/sources.py' <<< "$cached_files")" "1"
assert_eq "the scan follows /defaults into recon/ through the sys.path root" \
    "$(grep -cx 'recon-orchestrator recon/settings_registry.py' <<< "$cached_files")" "1"
assert_eq "the scan follows ioc_match.py into the incident matcher" \
    "$(grep -cx 'traffic-ingest scanners/supply_chain_common/intel.py' <<< "$cached_files")" "1"

assert_eq "a TruffleHog registry change rebuilds the scanner and restarts the orchestrator" \
    "$(effect 'scanners/trufflehog_scan/sources.py' | tr -s ' ')" " trufflehog-scanner | recon-orchestrator "
map() {
    local rebuild_core=() restart_only=()
    _map_core_changes "$1"
    echo "rebuild=${rebuild_core[*]-} restart=${restart_only[*]-}"
}
assert_eq "an orchestrator rebuilt anyway is not restarted as well" \
    "$(map $'graph_db/mixins/base_mixin.py\nrecon_orchestrator/Dockerfile')" "rebuild=recon-orchestrator agent restart="
assert_eq "docs and tests rebuild and restart nothing" \
    "$(effect $'docs/readmes/README.md\ntests/test_x.py\nskills/a/SKILL.md' | tr -d ' ')" "|"

section "a VERSION bump rebuilds every image that bakes it as a build argument"
# export_version turns VERSION into REDAMON_VERSION for compose, and an image
# that takes it as a build ARG keeps the old value until it is rebuilt.
assert_eq "REDAMON_VERSION comes from the VERSION file" \
    "$(declare -f export_version | grep -q 'get_version' && [[ "$VERSION_FILE" == "$REPO_ROOT/VERSION" ]] && echo yes)" "yes"
version_consumers=0
for entry in "${build_args[@]}"; do
    [[ "${entry#* }" == "REDAMON_VERSION" ]] || continue
    svc="${entry%% *}"
    version_consumers=$(( version_consumers + 1 ))
    built="$(effect 'VERSION')"; built="${built%%|*}"
    rebuilt=false
    for other in $built; do
        [[ "${image_of[$other]-}" == "${image_of[$svc]}" ]] && rebuilt=true
    done
    assert_eq "VERSION rebuilds $svc (it bakes REDAMON_VERSION)" "$rebuilt" "true"
done
assert_eq "at least the webapp takes REDAMON_VERSION as a build argument" \
    "$([[ $version_consumers -ge 1 ]] && echo yes)" "yes"

section "cmd_update runs every map"
assert_eq "_map_core_changes" "$(grep -c '^        _map_core_changes "$changed_files"$' "$REPO_ROOT/redamon.sh")" "1"
assert_eq "_map_tool_changes" "$(grep -c '^    _map_tool_changes "$changed_files"$' "$REPO_ROOT/redamon.sh")" "1"

echo ""
echo "PASS: $PASS  FAIL: $FAIL"
[[ $FAIL -eq 0 ]]
