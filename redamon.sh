#!/usr/bin/env bash
# =============================================================================
# RedAmon CLI - Simplified installation, update, and lifecycle management
# =============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VERSION_FILE="$SCRIPT_DIR/VERSION"
GVM_FLAG_FILE="$SCRIPT_DIR/.gvm-enabled"
GPU_ENABLED_FLAG_FILE="$SCRIPT_DIR/.gpu-enabled"
GPU_DISABLED_FLAG_FILE="$SCRIPT_DIR/.gpu-disabled"
TORCH_VARIANT_MARKER="$SCRIPT_DIR/.torch-variant"
KBASE_FLAG_FILE="$SCRIPT_DIR/.kbase-enabled"
KBASE_DISABLED_FLAG_FILE="$SCRIPT_DIR/.kbase-disabled"
LEGACY_SKIPKBASE_FLAG_FILE="$SCRIPT_DIR/.skipkbase"

# Service lists
CORE_SERVICES="postgres neo4j docker-broker recon-orchestrator kali-sandbox agent webapp"
# Build-only images run on demand (NOT long-running services). All live under the
# compose `tools` profile and the redamon-* tag namespace. ai-attack-surface is the
# AI Attack Surface scanner (garak/pyrit/giskard/promptfoo). wcvs is the Web Cache
# Vulnerability Scanner, run docker-in-docker by the recon container for the web
# cache poisoning module.
TOOL_IMAGES="redamon-recon:latest redamon-vuln-scanner:latest redamon-github-hunter:latest redamon-trufflehog:latest redamon-baddns:latest redamon-ai-attack-surface:latest redamon-codefix-sandbox:latest redamon-wcvs:latest redamon-supply-chain-analyzer:latest redamon-supply-chain:latest"
# Core services whose images are BUILT from this repo (postgres/neo4j are pulled,
# so they are absent here). Used to verify `up` has something to start; the tags
# are resolved through `docker compose config` so a renamed compose project or a
# clone directory other than "redamon" still matches.
CORE_BUILD_SERVICES="docker-broker recon-orchestrator kali-sandbox agent webapp"
DEV_COMPOSE="-f docker-compose.yml -f docker-compose.dev.yml"

# Free disk (GB) required before a Docker build starts. A full build has to fit
# the whole image set plus BuildKit's cache; a targeted rebuild of one or two
# services needs far less. See preflight_disk_gate().
DISK_FULL_BUILD_GB=40
DISK_PARTIAL_BUILD_GB=15

# Tracked paths that RedAmon REWRITES at runtime. A modified copy makes
# `git pull --ff-only` refuse to fast-forward, which stranded users on an old
# version behind a confusing "you may have local changes" error. They are
# machine-local bookkeeping (never user edits), so `update` restores them before
# pulling, and a commit that touches ONLY these is safe to discard when the
# branch has diverged (see _diverged_by_runtime_scribbles_only).
#
# recon/ is bind mounted rw into the spawned recon container, and two of its
# TRACKED data directories are re-downloaded there on a cache miss:
#   * mitre_db          - add_mitre.py, CVE/CAPEC/CWE, 15 files, 24h TTL
#   * wappalyzer_cache  - http_probe.py, technologies.json, 24h TTL
# Both drift whenever their upstream publishes. Directories are listed rather
# than files so a new sibling is covered automatically; entries may be either
# form, both are valid git pathspecs.
RUNTIME_TRACKED_PATHS="recon/main_recon_modules/data/mitre_db recon/main_recon_modules/data/wappalyzer_cache"

# Set by _update_pull ONLY when it self-heals a diverged checkout: the commit the
# checkout was really on before the discarded local commits. cmd_update must diff
# its changed-file -> service map from this, not from the commit it threw away.
UPDATE_BASE_HEAD=""

# Orchestrator-spawned containers that docker compose does NOT manage (they are
# created at runtime via the Docker API, so `compose down` leaves them behind and
# they must be wiped explicitly):
#   - AI Attack Surface scan containers:  redamon-ai-attack-<proj>-<run>
#   - On-demand local LLM (Ollama) judge/attacker:  redamon-local-llm
#   - CodeFix build sandboxes (T6/E10):  redamon-codefix-<job>
# Orchestrator-spawned, NON-compose-managed containers (repeated name filters are
# OR'd by docker ps). Includes the capture proxy + ingest pair: they are spawned by
# the orchestrator with restart:unless-stopped and live in the "capture" profile, so
# `docker compose down` (no --profile capture) would NOT stop them and they would
# leak past down/clean/purge — and hold the capture_* volumes purge tries to drop.
SPAWNED_CONTAINER_NAME_FILTERS=(--filter "name=redamon-ai-attack-" --filter "name=redamon-local-llm" --filter "name=redamon-codefix-" --filter "name=redamon-capture-proxy" --filter "name=redamon-traffic-ingest")
# The on-demand local LLM image (pulled at runtime, not built) + its models volume.
LOCAL_LLM_IMAGE="${LOCAL_LLM_IMAGE:-ollama/ollama:latest}"
LOCAL_LLM_VOLUME="${LOCAL_LLM_VOLUME:-redamon_llm_models}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

print_banner() {
    echo -e "${RED}${BOLD}"
    echo "  ____          _    _                         "
    echo " |  _ \\ ___  __| |  / \\   _ __ ___   ___  _ __"
    echo " | |_) / _ \\/ _\` | / _ \\ | '_ \` _ \\ / _ \\| '_ \\ "
    echo " |  _ <  __/ (_| |/ ___ \\| | | | | | (_) | | | |"
    echo " |_| \\_\\___|\\__,_/_/   \\_\\_| |_| |_|\\___/|_| |_|"
    echo -e "${NC}"
}

info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; }

# Read a `KEY=value` line from an env file and print the value (empty if the key
# or file is absent). CRITICAL: this must NEVER return non-zero. Callers assign
# its output as `x="$(_env_get ...)"` under `set -euo pipefail`, where a bare
# `grep` that finds nothing exits 1, `pipefail` propagates it, and `set -e` then
# aborts the whole script mid-assignment with no error message. That is exactly
# what made `./redamon.sh install` die silently right after generating the auth
# tokens on a FRESH install (#157): the new `.env` has no POSTGRES_DB line, so
# the TRAFFIC_INGEST_DATABASE_URL grep failed and killed the install before a
# single container was built. The trailing `|| true` pins the exit status to 0.
_env_get() {
    local key="$1" file="${2:-$SCRIPT_DIR/.env}"
    [ -f "$file" ] || return 0
    grep -E "^${key}=" "$file" 2>/dev/null | head -1 | cut -d= -f2- || true
}

# ---------------------------------------------------------------------------
# Adaptive build parallelism (memory-safe Docker builds)
# ---------------------------------------------------------------------------
# The Next.js `webapp` image build peaks at several GB of RAM. Building it in
# parallel with the heavy `agent` image (pip install + large layer export) has
# OOM-killed the webapp build on low-memory hosts ("Killed" / exit code 137).
# Two-layer mitigation, applied to EVERY `docker compose build` in this script
# via compose_build():
#   Layer 1: always build `webapp` on its own first. Once built its layers are
#            cached, so it never compiles concurrently with another image.
#   Layer 2: build the remaining images in BATCHES sized from the memory/CPU
#            actually available to the Docker BUILD ENGINE.
#
# Layer 2 pages the service list through `docker compose build` N names at a time
# rather than handing over the whole list with COMPOSE_PARALLEL_LIMIT set. That
# env var is only a hint: Compose v5 / Docker 29 delegate every build to bake,
# which hands all targets to buildx in ONE invocation and starts them together.
# Issue #171 is what that looks like in practice -- a host that logged
# "parallelism=3" then built 16 images at once, starving pip of bandwidth until it
# timed out. A batch cannot exceed its own length, so the cap holds regardless of
# what the builder does with the hint (which is still set, for older Compose).
# The cost is a barrier between batches; that is the point of the guarantee.
#
# Cross-platform: on macOS/Windows the Docker Desktop builder runs inside a Linux
# VM whose memory is capped independently of host RAM, so reading host RAM would
# be misleading. `docker info` reports the engine's real limits and is correct on
# Linux, macOS and Windows alike; host probing (/proc, sysctl) is only a fallback.
#
# Override: REDAMON_BUILD_PARALLEL=N forces the limit (N>=1), =0 leaves it
# unbounded. webapp isolation always applies regardless of the override.

BUILD_MEM_MB=0
BUILD_NCPU=1
BUILD_RES_SOURCE="unknown"

# Query a single `docker info` field, guarding against a wedged daemon. `timeout`
# is not present on stock macOS, so use it only when available.
_docker_info_field() {
    local field="$1" out=""
    if command -v timeout >/dev/null 2>&1; then
        out="$(timeout 8 docker info --format "{{.$field}}" 2>/dev/null)" || out=""
    else
        out="$(docker info --format "{{.$field}}" 2>/dev/null)" || out=""
    fi
    printf '%s' "$out"
}

# Populate BUILD_MEM_MB / BUILD_NCPU / BUILD_RES_SOURCE.
detect_build_resources() {
    local mem_bytes ncpu

    # Primary source: the Docker engine's own view (VM-aware on Mac/Windows).
    mem_bytes="$(_docker_info_field MemTotal)"
    ncpu="$(_docker_info_field NCPU)"
    mem_bytes="${mem_bytes//[^0-9]/}"
    ncpu="${ncpu//[^0-9]/}"

    if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
        BUILD_MEM_MB=$(( mem_bytes / 1048576 ))
        BUILD_RES_SOURCE="docker info"
    else
        # Fallback: probe the host OS directly.
        case "$(uname -s 2>/dev/null || echo unknown)" in
            Darwin)
                mem_bytes="$(sysctl -n hw.memsize 2>/dev/null || echo 0)"
                mem_bytes="${mem_bytes//[^0-9]/}"
                if [[ -n "$mem_bytes" && "$mem_bytes" -gt 0 ]]; then
                    BUILD_MEM_MB=$(( mem_bytes / 1048576 ))
                fi
                BUILD_RES_SOURCE="sysctl (host)"
                ;;
            *)  # Linux, WSL2, Git Bash/MSYS all expose /proc/meminfo
                if [[ -r /proc/meminfo ]]; then
                    local mem_kb
                    mem_kb="$(awk '/^MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || echo 0)"
                    mem_kb="${mem_kb//[^0-9]/}"
                    if [[ -n "$mem_kb" && "$mem_kb" -gt 0 ]]; then
                        BUILD_MEM_MB=$(( mem_kb / 1024 ))
                    fi
                    BUILD_RES_SOURCE="/proc/meminfo (host)"
                fi
                ;;
        esac
    fi

    # CPU count: docker info value, else nproc, else sysctl, else 1.
    if [[ -z "$ncpu" || "$ncpu" -lt 1 ]]; then
        if command -v nproc >/dev/null 2>&1; then
            ncpu="$(nproc 2>/dev/null || echo 1)"
        elif [[ "$(uname -s 2>/dev/null || echo unknown)" == "Darwin" ]]; then
            ncpu="$(sysctl -n hw.logicalcpu 2>/dev/null || echo 1)"
        else
            ncpu=1
        fi
        ncpu="${ncpu//[^0-9]/}"
    fi
    if [[ -z "$ncpu" || "$ncpu" -lt 1 ]]; then ncpu=1; fi
    BUILD_NCPU="$ncpu"

    # Third resource that decides whether a build can finish: the filesystem
    # Docker writes images to. Resolved here with the others so a single
    # detect_build_resources() call answers all of "can this build run?", and so
    # stubbing that one function in tests stubs resource detection completely.
    local root; root="$(_docker_info_field DockerRootDir)"
    if [[ -n "$root" && -d "$root" ]]; then
        BUILD_DISK_PATH="$root"
    else
        BUILD_DISK_PATH="$SCRIPT_DIR"
    fi
}

# Echo the chosen COMPOSE_PARALLEL_LIMIT. "0" means "leave unbounded".
# Assumes detect_build_resources() has already run.
pick_parallelism() {
    # Explicit override wins and skips heuristics entirely.
    if [[ -n "${REDAMON_BUILD_PARALLEL:-}" ]]; then
        local ov="${REDAMON_BUILD_PARALLEL//[^0-9]/}"
        if [[ -z "$ov" ]]; then ov=1; fi
        printf '%s' "$ov"
        return
    fi

    # Could not detect memory -> be conservative (serial).
    if [[ "$BUILD_MEM_MB" -le 0 ]]; then
        printf '1'
        return
    fi

    # Reserve headroom for the OS plus RedAmon containers that stay running
    # during `update` (neo4j/postgres/agent), and budget ~2GB per concurrent
    # heavy build.
    local reserve=2560 per_build=2048 usable mem_bound parallel
    usable=$(( BUILD_MEM_MB - reserve ))
    if [[ "$usable" -lt "$per_build" ]]; then
        mem_bound=1
    else
        mem_bound=$(( usable / per_build ))
    fi

    parallel="$mem_bound"
    if [[ "$BUILD_NCPU" -lt "$parallel" ]]; then parallel="$BUILD_NCPU"; fi
    if [[ "$parallel" -lt 1 ]]; then parallel=1; fi
    if [[ "$parallel" -gt 6 ]]; then parallel=6; fi
    printf '%s' "$parallel"
}

# Warn when the engine has so little memory that even the isolated webapp build
# may OOM -- no scheduling can fix that, the user must grant more memory.
maybe_warn_low_memory() {
    if [[ "$BUILD_MEM_MB" -gt 0 && "$BUILD_MEM_MB" -lt 5120 ]]; then
        warn "Low build memory: ~$(( BUILD_MEM_MB / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE}); the webapp build may still run out of memory."
        case "$(uname -s 2>/dev/null || echo unknown)" in
            Darwin|MINGW*|MSYS*|CYGWIN*)
                warn "  Increase it in Docker Desktop > Settings > Resources > Memory (6GB+ recommended), then re-run."
                ;;
            *)
                if grep -qi microsoft /proc/version 2>/dev/null; then
                    warn "  On WSL2, raise memory via %UserProfile%\\.wslconfig ([wsl2] memory=6GB), run 'wsl --shutdown', then re-run."
                else
                    warn "  Consider adding swap: sudo fallocate -l 8G /swapfile && sudo chmod 600 /swapfile && sudo mkswap /swapfile && sudo swapon /swapfile"
                fi
                ;;
        esac
    fi
}

# =============================================================================
# Memory governor (Part 4): startup RAM gate + adaptive per-service cap export.
# Both reuse detect_build_resources() (docker info / /proc / sysctl) so the
# figures match the rest of this script. Sizes accept g/m/k suffixes or bytes.
# =============================================================================

# Convert a Docker-style size ("2g","2048m","1073741824") to whole MB. Empty on
# invalid input. Plain numbers are bytes (matches resource_governor.parse_size).
_size_to_mb() {
    local v="${1:-}"
    v="$(printf '%s' "$v" | tr 'A-Z' 'a-z' | tr -d ' ')"
    [[ -z "$v" ]] && { printf ''; return; }
    v="${v%b}"                              # tolerate trailing 'b' (e.g. 512mb)
    local unit="" num="$v"
    case "$v" in
        *k) unit=k; num="${v%k}" ;;
        *m) unit=m; num="${v%m}" ;;
        *g) unit=g; num="${v%g}" ;;
        *t) unit=t; num="${v%t}" ;;
    esac
    # Allow a decimal (e.g. 1.5g, 0.5g); plain number = bytes.
    [[ "$num" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf ''; return; }
    # awk keeps the fraction ('1.5g' -> 1536), which pure bash integer math loses.
    awk -v n="$num" -v u="$unit" 'BEGIN{
        m = (u=="k")?1024 : (u=="m")?1048576 : (u=="g")?1073741824 : (u=="t")?1099511627776 : 1;
        printf "%d", int(n*m/1048576);
    }'
}

# Free-space threshold for the RUNTIME warning: max(absolute floor, DISK_RESERVE_PCT
# of the filesystem). DISK_FULL_BUILD_GB stays absolute because it models image
# SIZES (a property of the images, not of the disk); this one models "enough room
# to keep operating", which is proportional to the disk you actually have.
_disk_reserve_gb() {
    local path="${1:-}" total pct floor=10
    pct="$(_pct_env DISK_RESERVE_PCT 10 1 90)"
    total="$(df -BG --output=size "$path" 2>/dev/null | tail -1 | tr -dc '0-9')"
    [[ "$total" =~ ^[0-9]+$ ]] || { printf '%s' "$floor"; return; }
    local want=$(( total * pct / 100 ))
    [[ "$want" -lt "$floor" ]] && want="$floor"
    printf '%s' "$want"
}

# Refuse to start when the host/VM can't hold the always-on core services, with
# a clear message, instead of failing mysteriously later. Returns 1 to abort.
# Override with REDAMON_SKIP_RAM_GATE=1 or REDAMON_MIN_RAM_MB=<mb>.
preflight_ram_gate() {
    [[ "${REDAMON_SKIP_RAM_GATE:-}" == "1" ]] && return 0
    detect_build_resources
    local required_mb baseline_mb headroom_mb
    if [[ -n "${REDAMON_MIN_RAM_MB:-}" ]]; then
        required_mb="${REDAMON_MIN_RAM_MB//[^0-9]/}"
    elif [[ -n "${SERVICE_BASELINE_MEM:-}" || -n "${OS_HEADROOM_MEM:-}" ]]; then
        # An operator pinned the budget: honour it verbatim.
        baseline_mb="$(_size_to_mb "${SERVICE_BASELINE_MEM:-6g}")"; [[ -z "$baseline_mb" ]] && baseline_mb=6144
        headroom_mb="$(_size_to_mb "${OS_HEADROOM_MEM:-2g}")";      [[ -z "$headroom_mb" ]] && headroom_mb=2048
        required_mb=$(( baseline_mb + headroom_mb ))
    else
        # Ask the ALLOCATOR whether this host can actually satisfy the software
        # floors of the services that will run. That makes the gate
        # PROFILE-AWARE: enabling GVM adds five more services with their own
        # minimums, so `--gvm` on an 8 GB host is now refused up front instead of
        # passing a flat 8 GB check and OOM-ing later.
        if allocate_memory; then
            return 0
        fi
        error "Insufficient memory: ~$(( ${BUILD_MEM_MB:-0} / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE:-unknown}),"
        error "  which cannot cover the minimums of the services this profile starts"
        error "  (short by ~$(( _ALLOC_SHORTFALL_MB / 1024 + 1 ))GB)."
        is_gvm_enabled 2>/dev/null && error "  The --gvm profile roughly doubles the requirement; try without it."
        is_kbase_enabled 2>/dev/null && error "  The Knowledge Base profile also adds to it."
        error "Free up memory, raise the Docker VM memory, or set REDAMON_SKIP_RAM_GATE=1 to override."
        return 1
    fi
    [[ -z "$required_mb" || "$required_mb" -le 0 ]] && return 0
    # ~512MB slack: docker-info MemTotal on a physical 8GB host reads ~7.7GB
    # (kernel/reserved), which should still pass an 8GB requirement.
    local threshold=$(( required_mb - 512 ))
    [[ "$threshold" -lt 0 ]] && threshold="$required_mb"
    if [[ "${BUILD_MEM_MB:-0}" -gt 0 && "$BUILD_MEM_MB" -lt "$threshold" ]]; then
        error "Insufficient memory for RedAmon core services: ~$(( BUILD_MEM_MB / 1024 ))GB available to Docker (source: ${BUILD_RES_SOURCE}), need ~$(( required_mb / 1024 ))GB."
        error "Free up memory, raise the Docker VM memory, or set REDAMON_SKIP_RAM_GATE=1 to override."
        return 1
    fi
    return 0
}

# =============================================================================
# Disk governor: refuse to START a build that cannot finish.
#
# The memory gate above stops a build from being OOM-killed; this stops it from
# running out of DISK. That failure mode is far nastier: BuildKit dies partway
# through ("no space left on device"), the half-written layers are cleaned up,
# and a host that was one image short can end up with no usable images at all —
# nothing listening on :3000 and a bare 502 from whatever proxy sits in front.
# Checking first costs milliseconds and turns a dead install into a clear message.
#
# Sizing: the built image set is ~70GB on disk after layer dedup (the three heavy
# ones are ai-attack-surface ~16GB, kali-sandbox ~15GB, agent ~11GB), and BuildKit
# needs working room for its cache on top. 40GB is the floor for the incremental
# work of one full build, NOT the total footprint — see "Disk sizing" in README.md
# for what a real deployment needs.
# =============================================================================

# Free space (whole GB) on the filesystem holding <path>. Empty when unknown.
# `df -Pk` is the POSIX form: GNU's --output=avail does not exist on macOS.
_disk_free_gb() {
    local path="${1:-}" kb=""
    [[ -z "$path" ]] && { printf ''; return; }
    kb="$(df -Pk -- "$path" 2>/dev/null | awk 'NR==2{print $4}')"
    kb="${kb//[^0-9]/}"
    [[ -z "$kb" ]] && { printf ''; return; }
    printf '%s' $(( kb / 1048576 ))
}

# The filesystem that Docker actually writes images to, which is often NOT the
# one holding this repo (/var/lib/docker, or a snap/devicemapper path, can be a
# separate volume). On Mac/Windows the root lives inside the Docker VM and is
# invisible from here, so fall back to the repo — the VM's disk image sits on
# that filesystem anyway, making it a fair proxy.
_docker_disk_path() {
    # Already resolved by detect_build_resources()? Reuse it.
    if [[ -n "${BUILD_DISK_PATH:-}" ]]; then
        printf '%s' "$BUILD_DISK_PATH"
        return
    fi
    local root
    root="$(_docker_info_field DockerRootDir)"
    if [[ -n "$root" && -d "$root" ]]; then
        printf '%s' "$root"
    else
        printf '%s' "$SCRIPT_DIR"
    fi
}

# preflight_disk_gate <required_gb> <what> [path]
# Returns 1 (and explains how to reclaim space) when the build cannot fit.
# <path> defaults to the Docker data directory; callers that already ran
# detect_build_resources() pass $BUILD_DISK_PATH so no second `docker info` is
# issued mid-build.
# Override with REDAMON_SKIP_DISK_GATE=1 or REDAMON_MIN_DISK_GB=<gb>.
preflight_disk_gate() {
    local required_gb="${1:-$DISK_FULL_BUILD_GB}" what="${2:-build}" path="${3:-}"
    [[ "${REDAMON_SKIP_DISK_GATE:-}" == "1" ]] && return 0
    if [[ -n "${REDAMON_MIN_DISK_GB:-}" ]]; then
        required_gb="${REDAMON_MIN_DISK_GB//[^0-9]/}"
        [[ -z "$required_gb" ]] && required_gb="$DISK_FULL_BUILD_GB"
    fi
    [[ "$required_gb" -le 0 ]] && return 0

    local free
    [[ -z "$path" ]] && path="$(_docker_disk_path)"
    free="$(_disk_free_gb "$path")"
    if [[ -z "$free" ]]; then
        # Unmeasurable (unusual df output, permissions). Never block on this:
        # a false negative here would be worse than the risk it guards against.
        warn "Could not read free disk space for Docker (${path}); skipping the disk check."
        return 0
    fi

    if [[ "$free" -lt "$required_gb" ]]; then
        error "Not enough disk space for the ${what}: ${free}GB free on ${path}, need ~${required_gb}GB."
        error "RedAmon's images total ~70GB on disk and the build needs working room on top."
        error "Reclaim space, then re-run:"
        error "    docker builder prune -af     # build cache (usually the biggest win)"
        error "    docker image prune -af       # unused images"
        error "    docker system df             # see what is actually using space"
        error "Override with REDAMON_SKIP_DISK_GATE=1 (the build may then fail part-way)."
        return 1
    fi

    # Passing but close: the build will probably finish, yet leaves no room for
    # the next one. Say so now rather than at the next update.
    local comfortable=$(( required_gb + required_gb / 2 ))
    if [[ "$free" -lt "$comfortable" ]]; then
        warn "Disk is tight: ${free}GB free on ${path} (~${comfortable}GB recommended for the ${what})."
        warn "  Free some space soon: docker builder prune -af"
    fi
    return 0
}

# =============================================================================
# Proportional memory allocator
#
# ONE input -- the host's MemTotal -- and every limit is a percentage of it.
# There are no fixed sizes here: a bigger host gets bigger limits, at every size,
# without touching config. The previous scheme gave each service an independent
# percentage with a hard ceiling, which meant the always-on services took 89% of
# an 8 GB host and 4% of a 512 GB one, and four services were not sized at all.
#
#   os_reserve = MemTotal x OS_RESERVE_PCT
#   usable     = MemTotal - os_reserve
#   services   = usable x SERVICES_PCT          <- the guaranteed budget
#   scan_pool  = usable - services              <- what admission may hand out
#   service_i  = services x weight_i / SUM(weights)
#
# TIERS. `mem_limit` is a ceiling, not a reservation, so unused headroom costs
# nothing and may be over-committed -- EXCEPT where the process really allocates
# its share up front. Neo4j pre-allocates the page cache and Postgres its
# shared_buffers, so those are `r` (reserved) and are never multiplied. Every
# other service is `b` (burst) and gets BURST_FACTOR x its fair share, so one
# busy service can use the headroom the others are not touching. A third tier
# `t` (transient) is for one-shot containers that exit before the stack is in
# use and whose ceiling covers reclaimable page cache rather than an anonymous
# allocation: those sit outside the over-commit accounting entirely.
#
# FLOORS are the only absolute numbers, and they are a property of the SOFTWARE
# (a JVM cannot boot in 128 MB), not of the host. They never bind at >= 8 GB; on
# a smaller host the allocator reports infeasible rather than handing out limits
# that cannot work. The one exception is GVM_DATA, whose requirement is set by
# the size of the Greenbone feed rather than by the host, so its per-container
# floor binds at every realistic host size -- see _GVM_DATA_MIN_MB.
#
# Every knob is a percentage and env-overridable. Keep the weights in sync with
# docs/readmes/README.MEMORY_GOVERNOR.md.
# =============================================================================

# name:weight(per-mille of the services pool):floor(MB):tier(r=reserved,b=burst,t=transient)
_MEM_SPECS_BASE="NEO4J:320:1024:r POSTGRES:80:256:r AGENT:180:768:b WEBAPP:180:512:b KALI:100:512:b RECON_ORCHESTRATOR:60:256:b CAPTURE_PROXY:40:128:b DOCKER_BROKER:20:96:b TRAFFIC_INGEST:20:96:b"
# Optional profiles ADD weight; the sum is renormalised, so enabling one shrinks
# everybody else proportionally instead of over-committing the host.
#
# GVM is a STACK, not a service. Sizing only gvmd left the three other
# long-running containers -- ospd-openvas (the actual scanner), redis (holds the
# whole VT feed, routinely multi-GB) and its own postgres -- with no mem_limit at
# all, so on a --gvm host they sat uncapped next to a carefully budgeted
# everything-else and could eat the scan pool and the OS reserve. GVM_DATA is one
# shared cap for the eight one-shot feed loaders: six of them have no depends_on,
# so they start concurrently and their memory stacks during setup.
_MEM_SPEC_GVM="GVMD:120:768:b GVM_OSPD:110:512:b GVM_REDIS:90:256:b GVM_POSTGRES:50:256:b GVM_DATA:40:192:t"
# GVM_DATA's share is the TOTAL for the loader group; the exported
# GVM_DATA_MEM is that divided by the container count, because ONE compose
# var caps all of them and six start concurrently. Counting the group once
# while applying it eight times would understate the worst case eightfold.
# Keep in step with the number of services carrying `mem_limit: ${GVM_DATA_MEM}`
# in docker-compose.yml (the stale-lock cleanup moved into gvm-postgres itself,
# so the count went 9 -> 8).
_GVM_DATA_CONTAINERS=8
# ...but the divide must not take the slice below what the loader actually needs.
# Every other spec exports its allocated MB, so its floor is a real floor; this
# one divides first, which turned the declared 192 MB into 24 MB per container
# and SIGKILLed the feed copy on every host from 12 GB to ~32 GB (issue #176).
# The images run `cp -r` over a multi-GB tree (the VT feed is ~2 GB / ~180k
# files) and the page cache that generates is charged to the cgroup, so the copy
# dies below ~128 MB. 512 leaves margin for a slower disk and a growing feed.
# Over-committing here is safe in a way it would not be for a service: these are
# one-shot containers that exit before any scan is admitted.
_GVM_DATA_MIN_MB=512
_MEM_SPEC_KB="KB_REFRESH:150:512:b"

# Results, published as parallel indexed arrays (NOT associative: redamon.sh
# supports macOS, whose system bash is 3.2). Read by persist_memory_env and
# cmd_status.
_ALLOC_NAMES=()
_ALLOC_MB=()
_ALLOC_FLOORS=()
_ALLOC_TIERS=()
_ALLOC_WEIGHTS=()
_ALLOC_OWNED=()
_ALLOC_OS_MB=0
_ALLOC_SERVICES_MB=0
_ALLOC_SCAN_MB=0
_ALLOC_TOTAL_MB=0
_ALLOC_FEASIBLE=1
_ALLOC_SHORTFALL_MB=0
_ALLOC_BURST_PCT=0

# Markers around the block in .env that the allocator owns and regenerates.
# Anything OUTSIDE it is the operator's and is never touched.
_MEM_BLOCK_BEGIN="# >>> redamon memory governor (auto) >>>"
_MEM_BLOCK_END="# <<< redamon memory governor <<<"

# True when VAR is assigned in .env OUTSIDE the managed block, i.e. an operator
# pin rather than something we wrote ourselves last run.
_env_pin_outside_block() {
    local var="$1" env_file="$SCRIPT_DIR/.env"
    [[ -r "$env_file" ]] || return 1
    # A BARE `VAR=` is a placeholder, not a pin. .env.example lists every knob
    # that way, so treating it as a pin would make the allocator skip the export
    # and leave compose interpolating an EMPTY mem_limit -- which fails to start
    # the whole stack on any .env copied from the example.
    awk -v b="$_MEM_BLOCK_BEGIN" -v e="$_MEM_BLOCK_END" -v v="$var" '
        $0 == b { inblk = 1; next }
        $0 == e { inblk = 0; next }
        !inblk && $0 ~ ("^[[:space:]]*" v "=[[:space:]]*[^[:space:]]") { found = 1 }
        END { exit(found ? 0 : 1) }
    ' "$env_file"
}

# "1.75" -> 175. Percent-integer so the rest stays integer bash math. Anything
# below 1.0 (which would SHRINK a ceiling below its fair share) clamps to 100.
_factor_to_pct() {
    local v="${1:-}"
    [[ "$v" =~ ^[0-9]+([.][0-9]+)?$ ]] || { printf '175'; return; }
    awk -v n="$v" 'BEGIN{ p = int(n*100 + 0.5); if (p < 100) p = 100; printf "%d", p }'
}

# Read a tuning knob from the shell environment, falling back to .env.
#
# redamon.sh deliberately does NOT source .env (it must not inherit every app
# var into its own shell), so a knob documented in .env.example would otherwise
# be SILENTLY INERT -- the operator sets SERVICES_PCT=70, nothing changes, and
# nothing says why. This is the same class of bug as the memory pins that used to
# be overwritten on every `up`. Values inside the governor's own managed block
# are skipped: those are outputs, not knobs.
_env_knob() {
    local var="$1" v="${!1:-}"
    [[ -n "$v" ]] && { printf '%s' "$v"; return; }
    local env_file="$SCRIPT_DIR/.env"
    [[ -r "$env_file" ]] || return 0
    awk -v b="$_MEM_BLOCK_BEGIN" -v e="$_MEM_BLOCK_END" -v v="$var" '
        $0 == b { inblk = 1; next }
        $0 == e { inblk = 0; next }
        !inblk && index($0, v "=") == 1 { val = substr($0, length(v) + 2) }
        END { gsub(/^[[:space:]]+|[[:space:]]+$/, "", val); print val }
    ' "$env_file"
}

# An integer percentage knob, with a default and a sane range.
_pct_env() {
    local var="$1" def="$2" lo="$3" hi="$4" v
    v="$(_env_knob "$var")"
    [[ "$v" =~ ^[0-9]+$ ]] || { printf '%s' "$def"; return; }
    [[ "$v" -lt "$lo" || "$v" -gt "$hi" ]] && { printf '%s' "$def"; return; }
    printf '%s' "$v"
}

# Total swap in MB (Linux/WSL; 0 elsewhere, which is the safe answer).
_swap_total_mb() {
    local kb=""
    [[ -r /proc/meminfo ]] && kb="$(awk '/^SwapTotal:/ { print $2; exit }' /proc/meminfo 2>/dev/null)"
    [[ "$kb" =~ ^[0-9]+$ ]] || { printf '0'; return; }
    printf '%d' $(( kb / 1024 ))
}

# Burst multiplier. Swap (or zram) lets a simultaneous peak degrade by paging
# instead of OOM-killing, so ceilings can be over-committed further when it
# exists -- but only if there is ENOUGH of it. Measured across 8G..128G hosts,
# burst 2.5 over-commits by a steady ~21% of RAM, so the cushion is required to
# cover that (25% for margin) instead of merely being present. A 64 MB zram
# device must not unlock a multi-GB over-commit.
_burst_pct() {
    local bf; bf="$(_env_knob BURST_FACTOR)"
    if [[ -n "$bf" ]]; then _factor_to_pct "$bf"; return; fi
    local total="${BUILD_MEM_MB:-0}" swap min_pct
    swap="$(_swap_total_mb)"
    min_pct="$(_pct_env BURST_SWAP_MIN_PCT 25 1 100)"
    if [[ "$total" -gt 0 && "$swap" -ge $(( total * min_pct / 100 )) ]]; then
        printf '250'
    else
        printf '175'
    fi
}

# The specs for the profiles that are actually enabled.
_mem_specs() {
    local specs="$_MEM_SPECS_BASE"
    is_gvm_enabled 2>/dev/null && specs="$specs $_MEM_SPEC_GVM"
    is_kbase_enabled 2>/dev/null && specs="$specs $_MEM_SPEC_KB"
    printf '%s' "$specs"
}

# True when VAR is pinned by the operator: in the shell environment, or in .env
# OUTSIDE the governor's managed block. Compose gives the shell priority over
# .env, so exporting a computed value over an operator's pin would silently
# override it -- the bug that made hand-tuned limits revert on every `up`.
_mem_pinned() {
    local var="$1"
    # ...but NOT a value this process exported itself on an earlier pass.
    # export_resource_caps runs more than once in a single run (e.g. cmd_update
    # recreates the core services after rebuilding), and without this the second
    # pass would mistake its own exports for operator pins, own nothing, and
    # write an EMPTY managed block.
    _mem_self_exported "$var" && return 1
    [[ -n "${!var:-}" ]] && return 0
    _env_pin_outside_block "$var"
}

# Vars this process has exported itself, as " A B C " for substring matching
# (bash 3.2: no associative arrays).
_MEM_SELF_EXPORTED=" "
_mem_self_exported() {
    case "$_MEM_SELF_EXPORTED" in *" $1 "*) return 0 ;; esac
    return 1
}

# Compute the allocation. Exports every *_MEM / NEO4J_* var that is not pinned.
# Returns 1 when the host cannot even satisfy the software floors, having still
# exported the floor values so callers that ignore the status get a sane stack.
allocate_memory() {
    detect_build_resources
    # Reset EVERY result, including _ALLOC_OWNED/_ALLOC_TOTAL_MB, before the
    # bail-out below: leaving them set would let persist_memory_env write a block
    # from a previous call's state on a host whose RAM we can no longer read.
    _ALLOC_NAMES=(); _ALLOC_MB=(); _ALLOC_OWNED=()
    _ALLOC_FEASIBLE=1; _ALLOC_SHORTFALL_MB=0; _ALLOC_TOTAL_MB=0
    [[ "${BUILD_MEM_MB:-0}" -le 0 ]] && return 0      # RAM undetectable: fail open

    local total="$BUILD_MEM_MB"
    local os_pct svc_pct burst_pct
    os_pct="$(_pct_env OS_RESERVE_PCT 8 1 50)"
    svc_pct="$(_pct_env SERVICES_PCT 65 10 95)"
    burst_pct="$(_burst_pct)"

    local os_mb usable_mb services_mb scan_mb blast_mb
    os_mb=$(( total * os_pct / 100 ))
    usable_mb=$(( total - os_mb ))
    services_mb=$(( usable_mb * svc_pct / 100 ))
    scan_mb=$(( usable_mb - services_mb ))
    # Nothing may take more than this share of the host, so one runaway service
    # cannot starve the databases. Proportional, mirroring PER_CONTAINER_MAX in
    # recon_orchestrator/resource_governor.py.
    blast_mb=$(( total * "$(_pct_env BLAST_PCT 55 20 90)" / 100 ))

    # Parse the specs ONCE into parallel arrays; the passes below then need no
    # re-parsing (and no subshells) per service.
    local spec name weight floor tier w_override wsum=0 floorsum=0
    _ALLOC_FLOORS=(); _ALLOC_TIERS=(); _ALLOC_WEIGHTS=()
    for spec in $(_mem_specs); do
        IFS=':' read -r name weight floor tier <<< "$spec"
        # A per-service weight override keeps the model proportional: it changes
        # the SHARE, never a size.
        w_override="$(_env_knob "REDAMON_WEIGHT_${name}")"
        [[ "$w_override" =~ ^[0-9]+$ ]] && weight="$w_override"
        [[ "$weight" =~ ^[0-9]+$ ]] || weight=0
        wsum=$(( wsum + weight ))
        floorsum=$(( floorsum + floor ))
        _ALLOC_NAMES+=("$name")
        _ALLOC_WEIGHTS+=("$weight")
        _ALLOC_FLOORS+=("$floor")
        _ALLOC_TIERS+=("$tier")
    done
    [[ "$wsum" -le 0 ]] && wsum=1

    local i n=${#_ALLOC_NAMES[@]}

    # Infeasible: the software's own minimums exceed the services budget. Pin
    # everyone at their floor, skip the burst multiplier (a host that cannot even
    # meet the minimums must not be handed over-committed ceilings), and report
    # it -- preflight_ram_gate turns this into the refusal.
    if [[ "$floorsum" -gt "$services_mb" ]]; then
        _ALLOC_FEASIBLE=0
        _ALLOC_SHORTFALL_MB=$(( floorsum - services_mb ))
        for (( i = 0; i < n; i++ )); do _ALLOC_MB[$i]="${_ALLOC_FLOORS[$i]}"; done
        _ALLOC_OS_MB="$os_mb"; _ALLOC_SERVICES_MB="$services_mb"
        _ALLOC_SCAN_MB="$scan_mb"; _ALLOC_TOTAL_MB="$total"
        _mem_export_all
        return 1
    fi

    # --- fair shares, then raise anyone under its floor and reclaim the deficit
    # --- proportionally from those still above theirs. Iterate to a fixpoint.
    for (( i = 0; i < n; i++ )); do
        _ALLOC_MB[$i]=$(( services_mb * ${_ALLOC_WEIGHTS[$i]} / wsum ))
    done

    local pass deficit above cur
    for pass in 1 2 3 4 5; do
        deficit=0; above=0
        for (( i = 0; i < n; i++ )); do
            floor="${_ALLOC_FLOORS[$i]}"; cur="${_ALLOC_MB[$i]}"
            if [[ "$cur" -lt "$floor" ]]; then
                deficit=$(( deficit + floor - cur ))
            else
                above=$(( above + cur - floor ))
            fi
        done
        [[ "$deficit" -eq 0 ]] && break
        [[ "$above" -le 0 ]] && break
        for (( i = 0; i < n; i++ )); do
            floor="${_ALLOC_FLOORS[$i]}"; cur="${_ALLOC_MB[$i]}"
            if [[ "$cur" -lt "$floor" ]]; then
                _ALLOC_MB[$i]="$floor"
            else
                _ALLOC_MB[$i]=$(( cur - (cur - floor) * deficit / above ))
            fi
        done
    done

    # --- clamp the burst so the worst case cannot exceed what physically exists.
    #
    # BURST_FACTOR is what the operator ASKS for; it is not automatically safe.
    # A ceiling is only over-committable to the extent there is RAM+swap to
    # absorb a simultaneous peak, and how much headroom that leaves depends on
    # the host AND on which profiles are enabled -- enabling GVM adds five more
    # burst-tier services, and a fixed 2.5 then promised ~10 GB more than a
    # 31.7 GB host could back. Derive the ceiling instead of assuming one:
    #
    #   cushion   = MemTotal + swap - os_reserve - reserved_total
    #   max_burst = cushion / burst_fair_total
    #
    # so `os + reserved + SUM(burst ceilings) <= MemTotal + swap` holds by
    # construction at every host size and every profile combination.
    local reserved_total=0 burst_fair=0
    for (( i = 0; i < n; i++ )); do
        case "${_ALLOC_TIERS[$i]}" in
            # TRANSIENT: one-shot containers that exit before the stack is in
            # use, and whose ceiling is headroom for RECLAIMABLE page cache (a
            # `cp` of a big tree), not an anonymous allocation. Counting that as
            # a concurrent claim on RAM is what drove the GVM loaders down to
            # 24 MB and OOM-killed the feed copy (#176). Excluded from both sides
            # of the cushion equation.
            t) ;;
            b) burst_fair=$(( burst_fair + _ALLOC_MB[i] )) ;;
            *) reserved_total=$(( reserved_total + _ALLOC_MB[i] )) ;;
        esac
    done
    local cushion max_burst
    local swap_mb; swap_mb="$(_swap_total_mb)"
    [[ "$swap_mb" =~ ^[0-9]+$ ]] || swap_mb=0   # never let an empty read poison the sum
    cushion=$(( total + swap_mb - os_mb - reserved_total ))
    if [[ "$burst_fair" -gt 0 && "$cushion" -gt 0 ]]; then
        max_burst=$(( cushion * 100 / burst_fair ))
        [[ "$max_burst" -lt 100 ]] && max_burst=100
        [[ "$burst_pct" -gt "$max_burst" ]] && burst_pct="$max_burst"
    fi
    _ALLOC_BURST_PCT="$burst_pct"

    # --- burst multiplier on ceiling-type services only, then the blast bound
    for (( i = 0; i < n; i++ )); do
        cur="${_ALLOC_MB[$i]}"; floor="${_ALLOC_FLOORS[$i]}"
        [[ "${_ALLOC_TIERS[$i]}" == "b" ]] && cur=$(( cur * burst_pct / 100 ))
        [[ "$cur" -gt "$blast_mb" ]] && cur="$blast_mb"
        [[ "$cur" -lt "$floor" ]] && cur="$floor"
        _ALLOC_MB[$i]="$cur"
    done

    _ALLOC_OS_MB="$os_mb"
    _ALLOC_SERVICES_MB="$services_mb"
    _ALLOC_SCAN_MB="$scan_mb"
    _ALLOC_TOTAL_MB="$total"

    _mem_export_all
    [[ "$_ALLOC_FEASIBLE" -eq 1 ]]
}

# Export the computed values, skipping anything the operator pinned. Neo4j is
# special: its container limit must exceed heap + page cache or the JVM is
# OOM-killed at boot, so the three are derived together from its one share.
_mem_export_all() {
    local i n=${#_ALLOC_NAMES[@]} name mb var
    _ALLOC_OWNED=()
    for (( i = 0; i < n; i++ )); do
        name="${_ALLOC_NAMES[$i]}"; mb="${_ALLOC_MB[$i]}"
        if [[ "$name" == "NEO4J" ]]; then
            local heap pc eff_heap eff_pc
            heap=$(( mb * 50 / 100 ))
            pc=$(( mb * 35 / 100 ))
            # The remaining 15% is JVM overhead (metaspace, threads, direct
            # buffers) -- proportional, replacing a flat +1024m that made the
            # container limit drift relative to the heap on large hosts.
            _mem_own NEO4J_HEAP      "${heap}m"
            _mem_own NEO4J_PAGECACHE "${pc}m"
            # Derive the container limit from the EFFECTIVE heap/pagecache so an
            # operator's pin can never produce a cap below the JVM heap.
            eff_heap="$(_size_to_mb "${NEO4J_HEAP:-${heap}m}")"; [[ -z "$eff_heap" ]] && eff_heap="$heap"
            eff_pc="$(_size_to_mb "${NEO4J_PAGECACHE:-${pc}m}")"; [[ -z "$eff_pc" ]] && eff_pc="$pc"
            [[ $(( eff_heap + eff_pc )) -ge "$mb" ]] && mb=$(( (eff_heap + eff_pc) * 100 / 85 ))
            _mem_own NEO4J_MEM "${mb}m"
            _ALLOC_MB[$i]="$mb"
            continue
        fi
        if [[ "$name" == "GVM_DATA" ]]; then
            # One var caps N containers: export the PER-CONTAINER slice, never
            # below the floor the copy needs (see _GVM_DATA_MIN_MB).
            local per=$(( mb / _GVM_DATA_CONTAINERS ))
            [[ "$per" -lt "$_GVM_DATA_MIN_MB" ]] && per="$_GVM_DATA_MIN_MB"
            _mem_own GVM_DATA_MEM "${per}m"
            _ALLOC_MB[$i]=$(( per * _GVM_DATA_CONTAINERS ))
            continue
        fi
        _mem_own "${name}_MEM" "${mb}m"
    done
    # Feed the scan governor from the SAME computation, so admission stops
    # guessing. service_baseline is the guaranteed services budget (NOT the sum
    # of burst ceilings: modelling ceilings as usage would refuse scans while RAM
    # sat free), which makes the orchestrator's
    #   scan_pool = total - os_headroom - service_baseline
    # identical to ours by construction.
    _mem_own OS_HEADROOM_MEM      "${_ALLOC_OS_MB}m"
    _mem_own SERVICE_BASELINE_MEM "${_ALLOC_SERVICES_MB}m"
}

# Export VAR unless the operator pinned it, recording the ones we own so
# persist_memory_env writes exactly those into the managed block. Without this
# record a pinned var would be written back as an EMPTY assignment, which makes
# compose interpolate `mem_limit:` to nothing and refuse to start.
_mem_own() {
    local var="$1" val="$2"
    _mem_pinned "$var" && return 0
    export "$var=$val"
    _ALLOC_OWNED+=("$var")
    _mem_self_exported "$var" || _MEM_SELF_EXPORTED="${_MEM_SELF_EXPORTED}${var} "
}

# Export a CPU cap of min(compose default, detected cores) for VAR, unless the
# operator pinned it. Skips when the core count is unknown, leaving the compose
# default in place.
_export_cpu_cap() {
    local var="$1" default="$2" n="${BUILD_NCPU:-0}"
    [[ -n "${!var:-}" ]] && return 0                 # shell/env override wins
    # A pin in .env must win too: compose gives the shell environment priority
    # over .env, so exporting here would silently override the operator's value.
    [[ -r "$SCRIPT_DIR/.env" ]] && grep -q "^[[:space:]]*${var}=" "$SCRIPT_DIR/.env" && return 0
    [[ "$n" -lt 1 ]] && return 0
    [[ "$default" -gt "$n" ]] && default="$n"
    export "$var=$default"
}

# #163: docker-compose.yml carries generous `cpus:` defaults sized for a
# workstation (neo4j 8, kali 10, agent 8). The Docker daemon REJECTS any cpus
# value above the host core count -- "range of CPUs is from 0.01 to 4.00, as
# there are only 4 CPUs available" -- so on a 4-vCPU VM every `docker compose
# up` died before the stack came up. Clamp each cap to the detected core count.
# `cpus:` is a limit, not a reservation, so clamping loses nothing: the core
# count was already the real ceiling. Keep these defaults in sync with
# docker-compose.yml and tooling/deploy/single-host/deploy.sh's cap_cpus block.
export_cpu_caps() {
    [[ -z "${BUILD_NCPU:-}" ]] && detect_build_resources
    _export_cpu_cap POSTGRES_CPUS 4
    _export_cpu_cap NEO4J_CPUS 8
    _export_cpu_cap KALI_CPUS 10
    _export_cpu_cap RECON_ORCHESTRATOR_CPUS 4
    _export_cpu_cap AGENT_CPUS 8
    _export_cpu_cap WEBAPP_CPUS 4
    _export_cpu_cap DOCKER_BROKER_CPUS 2
}

# The Docker host's LAN IP, exported so the agent can SUGGEST it as the reverse-
# shell LHOST (issue #180). The tools run inside kali-sandbox on a private 172.x
# bridge that a real target cannot reach; the reachable address is the host's own
# LAN IP, and port 4444 is forwarded host->container. A container cannot discover
# this itself, so it is detected here on the host and passed in via env.
#
# IPv4 only: the webapp validates agentLhost against an IPv4 regex, so a v6/zoned
# value would produce a suggestion the form then refuses to save. Best-effort:
# on any failure it stays empty and the agent falls back to asking the operator.
detect_host_lan_ip() {
    local ip=""
    # `ip route get` reveals the src address of the default route -- the interface
    # that reaches off-box. `-4` forces IPv4. On a VPN/multi-homed host this may be
    # the wrong NIC; the operator overrides with a HOST_LAN_IP pin (see export).
    if command -v ip >/dev/null 2>&1; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | grep -oE 'src [0-9.]+' | awk '{print $2}' | head -n1)"
    fi
    # Fallback: first IPv4 that `hostname -I` lists (skips v6 tokens).
    if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
        ip="$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -oE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | head -n1)"
    fi
    # Reject anything that is not a bare IPv4 dotted quad.
    [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || ip=""
    printf '%s' "$ip"
}

# Export HOST_LAN_IP for the agent container. Mirrors _export_cpu_cap's pin
# precedence (shell env, then .env) with ONE deviation: a .env pin must carry a
# NON-EMPTY value. `.env.example` ships a bare `HOST_LAN_IP=` placeholder, and a
# plain `grep var=` (as _export_cpu_cap uses) would read that empty line as a pin
# and suppress detection for anyone who seeds .env from the example. Never
# persisted into the managed .env block: a saved IP becomes a stale pin the moment
# the operator switches networks, so it is recomputed every run.
export_host_lan_ip() {
    [[ -n "${HOST_LAN_IP:-}" ]] && return 0        # shell/env override wins
    [[ -r "$SCRIPT_DIR/.env" ]] && grep -qE "^[[:space:]]*HOST_LAN_IP=[^[:space:]]" "$SCRIPT_DIR/.env" && return 0
    local detected
    detected="$(detect_host_lan_ip)"
    if [[ -z "$detected" ]]; then
        warn "could not detect the host LAN IP -- the agent will ask for LHOST instead of suggesting it (set HOST_LAN_IP=<ip> to override)"
        return 0
    fi
    export HOST_LAN_IP="$detected"
}

# Every var the allocator owns. Used by the migration and the managed block.
_mem_managed_vars() {
    local spec name
    for spec in $(_mem_specs); do
        name="${spec%%:*}"
        if [[ "$name" == "NEO4J" ]]; then
            printf 'NEO4J_MEM\nNEO4J_HEAP\nNEO4J_PAGECACHE\n'
        else
            printf '%s_MEM\n' "$name"
        fi
    done
    printf 'OS_HEADROOM_MEM\nSERVICE_BASELINE_MEM\n'
}

# One-time migration, run only when .env has no managed block yet (i.e. the first
# `up` after this feature landed). Hand-pinned sizes from before the allocator
# existed -- typically an operator firefighting an OOM with WEBAPP_MEM=4g -- are
# reported and folded into the block, so the host actually adopts the
# proportional values. Once the block exists, anything outside it is a DELIBERATE
# pin and is left alone forever.
_mem_migrate_legacy_pins() {
    local env_file="$SCRIPT_DIR/.env"
    [[ -r "$env_file" ]] || return 0
    grep -qF "$_MEM_BLOCK_BEGIN" "$env_file" 2>/dev/null && return 0   # not the first run

    local var found=0 old
    while read -r var; do
        [[ -z "$var" ]] && continue
        # Only a real value counts; a bare `VAR=` placeholder (as .env.example
        # ships them) is nothing to migrate and must be left in place.
        old="$(grep -E "^[[:space:]]*${var}=[[:space:]]*[^[:space:]]" "$env_file" 2>/dev/null | tail -1)" || true
        [[ -z "$old" ]] && continue
        if [[ "$found" -eq 0 ]]; then
            info "memory governor: folding hand-pinned limits into the managed block"
            info "  (to keep one, re-add it BELOW the block after this run)"
            found=1
        fi
        info "  ${old#*=} -> computed   (${var})"
        _env_strip_var "$env_file" "$var"
    done <<< "$(_mem_managed_vars)"
    return 0
}

# Remove every assignment of VAR from a .env file, in place, preserving mode.
_env_strip_var() {
    local env_file="$1" var="$2" tmp
    tmp="$(mktemp "${env_file}.XXXXXX")" || return 0
    grep -vE "^[[:space:]]*${var}=" "$env_file" > "$tmp" 2>/dev/null || true
    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$env_file"
}

# Write the computed allocation into a managed block in .env.
#
# WHY THIS EXISTS: the values used to be `export`ed into a shell that then
# exited, so they lived exactly as long as one redamon.sh process. Any later
# bare `docker compose up -d` -- which is what most people run locally, and what
# had been run on the server this feature came from -- silently fell back to the
# compose defaults, a fixed ~12.6 GB budget with no relation to the machine.
# Persisting makes the allocation hold no matter how the stack is started, and
# makes it visible to the operator.
#
# The block is REGENERATED every run (so resizing the host re-tunes automatically)
# and everything outside it is left untouched.
persist_memory_env() {
    local env_file="$SCRIPT_DIR/.env"
    [[ "${_ALLOC_TOTAL_MB:-0}" -gt 0 ]] || return 0     # nothing computed; leave .env alone
    touch "$env_file" 2>/dev/null || return 0

    local tmp
    tmp="$(mktemp "${env_file}.XXXXXX")" || return 0
    # Everything outside the block, verbatim (secrets, operator pins, comments).
    awk -v b="$_MEM_BLOCK_BEGIN" -v e="$_MEM_BLOCK_END" '
        $0 == b { inblk = 1; next }
        $0 == e { inblk = 0; next }
        !inblk { print }
    ' "$env_file" > "$tmp"
    # Trim trailing blank lines, or the leading newline we print below would make
    # the file grow by one line on every run.
    awk '{ l[NR] = $0 }
         END { last = NR; while (last > 0 && l[last] ~ /^[[:space:]]*$/) last--;
               for (i = 1; i <= last; i++) print l[i] }' \
        "$tmp" > "${tmp}.2" && mv -f "${tmp}.2" "$tmp"

    {
        printf '\n%s\n' "$_MEM_BLOCK_BEGIN"
        printf '# Generated by redamon.sh from MemTotal=%sMB. Do not edit: this block is\n' "$_ALLOC_TOTAL_MB"
        printf '# rewritten on every `up`, so it re-tunes itself when the host is resized.\n'
        printf '# To pin a value, set it ANYWHERE OUTSIDE this block: the block then omits it\n'
        printf '# entirely, so there is never a competing assignment and order does not matter.\n'
        printf '# os_reserve=%sMB  services=%sMB  scan_pool=%sMB\n' \
            "$_ALLOC_OS_MB" "$_ALLOC_SERVICES_MB" "$_ALLOC_SCAN_MB"
        # ONLY the vars we own. A pinned one is deliberately absent, so compose
        # keeps reading the operator's value from outside the block.
        local var
        for var in "${_ALLOC_OWNED[@]:-}"; do
            # `${!var:-}` (never a bare `${!var}`): the caller runs under `set -u`,
            # so a var that vanished between the export and now must not abort the
            # whole command mid-write.
            [[ -z "$var" || -z "${!var:-}" ]] && continue
            printf '%s=%s\n' "$var" "${!var}"
        done
        printf '%s\n' "$_MEM_BLOCK_END"
    } >> "$tmp"

    chmod 600 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$env_file"
}

# Public entry point: CPU caps + the proportional memory allocation, exported so
# docker-compose.yml `${VAR:-default}` picks them up, and persisted to .env so a
# bare `docker compose up` gets the same numbers. Kept as the name every cmd_*
# already calls. Never fails the caller -- an undersized host is reported by
# preflight_ram_gate, which reads allocate_memory's status directly.
export_resource_caps() {
    detect_build_resources
    # CPU caps first: unlike the memory caps they do not depend on RAM
    # detection, so they must be applied before the undetectable-RAM bail-out.
    export_cpu_caps
    export_host_lan_ip
    _mem_migrate_legacy_pins
    allocate_memory || true
    persist_memory_env
    return 0
}

# Optional one-time compressed-RAM (zram) swap cushion so brief memory overshoots
# degrade gracefully (swap to compressed RAM) instead of OOM-killing. Linux-native
# host only; a NO-OP on macOS/Windows (Docker Desktop's VM manages its own swap)
# and when REDAMON_ENABLE_ZRAM != 1. Best-effort: never fatal, never interactive.
setup_zram() {
    [[ "${REDAMON_ENABLE_ZRAM:-}" == "1" ]] || return 0

    # Docker Desktop / WSL2 / mac: cannot add zram to the host VM from here.
    case "$(uname -s 2>/dev/null || echo unknown)" in
        Linux) ;;
        *) info "zram: skipped (not a native Linux host)"; return 0 ;;
    esac
    if grep -qi microsoft /proc/version 2>/dev/null; then
        info "zram: skipped (WSL2 manages its own memory)"; return 0
    fi
    # Already have zram swap active? Leave it.
    if swapon --show=NAME --noheadings 2>/dev/null | grep -q zram; then
        info "zram: already active"; return 0
    fi
    if ! command -v zramctl >/dev/null 2>&1; then
        warn "zram: zramctl not found; skipping (install util-linux/zram-tools to enable)"; return 0
    fi

    detect_build_resources
    local size="${REDAMON_ZRAM_SIZE:-}"
    if [[ -z "$size" ]]; then
        if [[ "${BUILD_MEM_MB:-0}" -le 0 ]]; then
            warn "zram: cannot size (RAM undetectable); set REDAMON_ZRAM_SIZE to enable"; return 0
        fi
        # Default: half of detected RAM, clamped to [512M, 8G].
        local half=$(( BUILD_MEM_MB / 2 ))
        [[ "$half" -gt 8192 ]] && half=8192
        [[ "$half" -lt 512 ]] && half=512
        size="${half}M"
    fi

    # Requires root; use sudo non-interactively so we never hang on a password.
    local SUDO=""
    if [[ "$(id -u)" != "0" ]]; then
        if sudo -n true 2>/dev/null; then SUDO="sudo -n"; else
            warn "zram: needs root and passwordless sudo is unavailable; skipping"; return 0
        fi
    fi

    local dev
    if dev="$($SUDO zramctl --find --size "$size" --algorithm zstd 2>/dev/null)" && [[ -n "$dev" ]]; then
        if $SUDO mkswap "$dev" >/dev/null 2>&1 && $SUDO swapon --priority 100 "$dev" 2>/dev/null; then
            success "zram: enabled ${size} compressed swap on ${dev}"
        else
            warn "zram: failed to enable swap on ${dev}; cleaning up"
            $SUDO zramctl --reset "$dev" 2>/dev/null || true
        fi
    else
        warn "zram: could not allocate a zram device; skipping"
    fi
    return 0
}

# Reclaim the BuildKit cache a rebuild just orphaned. Docker never collects this
# on its own: a rebuild writes NEW layers and leaves the previous version's
# behind unreferenced, so the cache grows by a few GB on every update and ends up
# the single biggest reclaimable item on a long-lived install (measured: ~23GB of
# orphaned cache on a box that had never pruned).
#
# `prune -f`, NEVER `prune -af`. The plain form drops only cache records that no
# existing image still references, so the cache backing the images we just built
# stays warm and the NEXT update is still incremental. `-af` would additionally
# wipe that warm cache while recovering no extra disk -- those bytes are SHARED
# with the images and stay on disk regardless -- turning every future rebuild
# into a cold one for nothing.
#
# Opt out with REDAMON_NO_AUTO_PRUNE=1. The builder cache is per-DAEMON, not
# per-project: there is no filter that scopes a prune to one compose project, so
# on a shared workstation this also evicts other projects' orphaned cache.
# Harmless on a dedicated deployment host, rude on a dev box.
prune_stale_build_cache() {
    [[ "${REDAMON_NO_AUTO_PRUNE:-}" == "1" ]] && return 0

    local out reclaimed=""
    # A prune failure (old daemon, wedged builder) must never turn a SUCCESSFUL
    # build into a failed command. This is opportunistic housekeeping, not part
    # of the build contract, so swallow everything and return 0.
    out="$(docker builder prune -f 2>/dev/null)" || return 0

    # `docker builder prune` ends with a "Total:  <size>" line. Report only when
    # something was actually freed, so the common no-op case stays silent.
    reclaimed="$(printf '%s\n' "$out" | awk '/^Total:/ {print $NF}' | tail -1)"
    if [[ -n "$reclaimed" && "$reclaimed" != "0B" ]]; then
        info "Reclaimed ${reclaimed} of stale build cache (disable: REDAMON_NO_AUTO_PRUNE=1)"
    fi
    return 0
}

# Echo the buildable compose targets for a `compose_build`-style arg list, one per
# line. `build --print` emits bake's own target group, so this is exactly the set
# of services that have a build section under the active profiles: a service that
# only pulls an image (neo4j, postgres, the gvm-* data containers) is never handed
# to `build`. Sorted so batch membership is reproducible run to run. Empty output
# (no bake support on an older Compose, or a wedged daemon) makes the caller fall
# back to one unbatched build -- which is also where COMPOSE_PARALLEL_LIMIT still
# works, so the degradation lands on the path that does not need batching.
_compose_build_targets() {
    docker compose "$@" --print 2>/dev/null | awk '
        /"targets"[[:space:]]*:[[:space:]]*\[/ { inside = 1; next }
        inside && /\]/                         { exit }
        inside {
            gsub(/[",]/, ""); gsub(/^[[:space:]]+|[[:space:]]+$/, "")
            if ($0 != "") print
        }' | sort
}

# Memory-safe replacement for `docker compose ... build ...`. Pass exactly the
# args that would follow `docker compose`, e.g.:
#   compose_build --profile tools build
#   compose_build --profile tools build recon vuln-scanner
#   compose_build build recon-orchestrator kali-sandbox agent webapp docker-broker
compose_build() {
    detect_build_resources
    local parallel; parallel="$(pick_parallelism)"

    # Split the arg list into the part before `build` (global flags such as
    # --profile tools), the build flags, and the service names. Batching has to
    # rebuild the command line, so the three groups are kept apart rather than
    # just counted.
    local -a pre=() flags=() svcs=()
    local seen_build=false has_webapp=false
    while [[ $# -gt 0 ]]; do
        if [[ "$seen_build" == false ]]; then
            pre+=("$1")
            if [[ "$1" == "build" ]]; then seen_build=true; fi
            shift; continue
        fi
        case "$1" in
            # Flags that consume the next token; without this their value would
            # be mistaken for a service name.
            --build-arg|--builder|-m|--memory|--provenance|--sbom|--ssh)
                flags+=("$1"); [[ $# -ge 2 ]] && { flags+=("$2"); shift; }
                shift; continue ;;
            -*) flags+=("$1"); shift; continue ;;
            *)  svcs+=("$1"); [[ "$1" == "webapp" ]] && has_webapp=true
                shift; continue ;;
        esac
    done
    local svc_count="${#svcs[@]}"

    # A build with no explicit service list builds everything -> webapp included.
    local isolate_webapp=false
    if [[ "$has_webapp" == true || "$svc_count" -eq 0 ]]; then
        isolate_webapp=true
    fi

    # Disk gate. Every build path in this script funnels through compose_build,
    # so gating here covers install, update, and the lazy ensure_tool_images
    # build with one check. Scale the requirement to the scope: an empty service
    # list means "build everything" (the ~48GB set), a named list is targeted.
    local need_gb="$DISK_PARTIAL_BUILD_GB" what="rebuild"
    if [[ "$svc_count" -eq 0 ]]; then
        need_gb="$DISK_FULL_BUILD_GB"; what="full image build"
    fi
    # Reuse the path detect_build_resources() just resolved: no extra `docker
    # info` round-trip, and the gate stays measurable even when a caller stubs
    # resource detection.
    if ! preflight_disk_gate "$need_gb" "$what" "${BUILD_DISK_PATH:-$SCRIPT_DIR}"; then
        return 1
    fi

    info "Docker build resources: ~$(( BUILD_MEM_MB / 1024 ))GB RAM / ${BUILD_NCPU} CPU (${BUILD_RES_SOURCE}); parallelism=${parallel}"
    maybe_warn_low_memory

    # Layer 1: build the RAM-heavy webapp on its own first.
    if [[ "$isolate_webapp" == true ]]; then
        info "Building webapp in isolation first (prevents out-of-memory during parallel build)..."
        docker compose build webapp
    fi

    # Layer 2: build the (remaining) images, at most $parallel at a time. If
    # webapp was in the set it is now cached, so re-passing it is a no-op.
    #
    # Capture the status instead of letting it propagate directly: Layer 3 has to
    # run in between, and it must not overwrite the build's exit code. `return
    # "$build_rc"` at the end restores the original contract, so a caller that
    # invokes compose_build bare still aborts under `set -e`, and one that wraps
    # it in `if ! compose_build ...` (cmd_update's tool build) still sees failure.
    local build_rc=0
    # `${arr[@]+"${arr[@]}"}` throughout: an empty array under `set -u` is an
    # unbound variable on bash 3.2 (stock macOS), which this script still runs on.
    local -a base=(${pre[@]+"${pre[@]}"} ${flags[@]+"${flags[@]}"})
    local -a batch_svcs=(${svcs[@]+"${svcs[@]}"})

    # "Build everything" arrives with no names to page through, so resolve the set
    # before batching it.
    if [[ "$svc_count" -eq 0 && "$parallel" -ge 1 ]]; then
        local target
        batch_svcs=()
        while IFS= read -r target; do
            [[ -n "$target" ]] && batch_svcs+=("$target")
        done < <(_compose_build_targets "${base[@]}")
    fi

    if [[ "$parallel" -ge 1 && "${#batch_svcs[@]}" -gt "$parallel" ]]; then
        local total="${#batch_svcs[@]}" i=0 n=0 batches
        batches=$(( (total + parallel - 1) / parallel ))
        while [[ "$i" -lt "$total" ]]; do
            n=$(( n + 1 ))
            local -a batch=("${batch_svcs[@]:i:parallel}")
            info "Build batch ${n}/${batches}: ${batch[*]}"
            COMPOSE_PARALLEL_LIMIT="$parallel" docker compose "${base[@]}" "${batch[@]}" \
                || { build_rc=$?; break; }
            i=$(( i + parallel ))
        done
    elif [[ "$parallel" -ge 1 ]]; then
        COMPOSE_PARALLEL_LIMIT="$parallel" docker compose "${base[@]}" ${svcs[@]+"${svcs[@]}"} \
            || build_rc=$?
    else
        # REDAMON_BUILD_PARALLEL=0 -> unbounded, one call, no pacing at all.
        docker compose "${base[@]}" ${svcs[@]+"${svcs[@]}"} || build_rc=$?
    fi

    # Layer 3: drop the cache the rebuild just orphaned. ONLY on success -- after
    # a failed build the "orphaned" cache is the partial work the retry wants to
    # resume from, and pruning it would force the retry to start cold.
    if [[ "$build_rc" -eq 0 ]]; then
        prune_stale_build_cache
    fi

    return "$build_rc"
}

# Best-effort POST to the orchestrator capture-proxy/start (idempotent reconcile:
# removes any stale instance, (re)spawns proxy + ingest on the current image using
# the orchestrator's .env-derived runtime knobs). Returns non-zero if there is no
# ORCHESTRATOR_API_KEY or the orchestrator is unreachable.
_capture_start_post() {
    local env_file="$SCRIPT_DIR/.env" okey="" port=""
    okey="$(_env_get ORCHESTRATOR_API_KEY "$env_file")"
    port="$(_env_get RECON_ORCH_PORT "$env_file")"
    port="${port:-8010}"
    [ -z "$okey" ] && return 1
    curl -fsS -X POST "http://127.0.0.1:${port}/capture-proxy/start" \
        -H "X-Orchestrator-Key: ${okey}" -H 'Content-Type: application/json' \
        -o /dev/null 2>/dev/null
}

# True (0) if the HTTP Traffic Capture master switch is on for any user. The proxy
# is a global singleton, so one enabled operator means it should run.
_capture_master_switch_on() {
    local v
    v="$(docker compose exec -T postgres psql -U redamon -d redamon -tAc \
        "SELECT bool_or(capture_proxy_enabled) FROM user_settings;" 2>/dev/null | tr -d '[:space:]')"
    [ "$v" = "t" ]
}

# If the capture proxy is currently running, ask the orchestrator to recreate it so
# a freshly-rebuilt redamon-capture-proxy:latest actually goes live — a running
# container otherwise keeps the OLD image (security fixes to the addon / egress /
# ingest / redaction would NOT apply until the next Settings toggle). Best-effort.
# A UI-customised port/scope reverts to the .env defaults until the next Settings save.
_reconcile_capture_if_running() {
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-capture-proxy$' || return 0
    info "Refreshing the running capture proxy onto the rebuilt image..."
    if _capture_start_post; then
        success "Capture proxy refreshed onto the new image."
    else
        warn "Could not refresh the running capture proxy (no ORCHESTRATOR_API_KEY or orchestrator unreachable); toggle HTTP Traffic Capture off/on in Settings to apply the update."
    fi
}

# The capture proxy + ingest are orchestrator-spawned (NOT compose-managed), so a
# stack restart / `up` leaves them down and nothing restarts them — recon then runs
# DIRECT ("capture degraded") and silently captures nothing. If the master switch is
# on, reconcile them here so capture survives a restart. Idempotent + best-effort;
# retries briefly while the just-started orchestrator becomes reachable.
ensure_capture_proxy_running() {
    _capture_master_switch_on || return 0
    docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-capture-proxy$' && return 0
    info "HTTP Traffic Capture is enabled — starting the capture proxy..."
    local i
    for i in 1 2 3 4 5 6 7 8; do
        if _capture_start_post; then success "Capture proxy started."; return 0; fi
        sleep 3
    done
    warn "HTTP Traffic Capture is on but the capture proxy could not be started (orchestrator not ready or ORCHESTRATOR_API_KEY missing). Re-run ./redamon.sh up, or toggle it in Settings."
}

get_version() {
    if [[ -f "$VERSION_FILE" ]]; then
        cat "$VERSION_FILE" | tr -d '[:space:]'
    else
        echo "unknown"
    fi
}

is_gvm_enabled() {
    [[ -f "$GVM_FLAG_FILE" ]]
}

is_kbase_enabled() {
    [[ -f "$KBASE_FLAG_FILE" ]]
}

# ---------------------------------------------------------------------------
# One-time layout migration (pre-6.9 flat root -> grouped root)
# ---------------------------------------------------------------------------
# The 6.9 reorganization moved whole directories under scanners/ services/
# tooling/ testing/ docs/ _local/. `git pull` moves only TRACKED files, so every
# git-IGNORED artefact the user owns stays behind at its old path while the new
# code reads the new one. Without this migration an upgrade silently loses:
#   - services/knowledge_base/data  : the FAISS index (KB reports empty and
#     _migrate_legacy_kbase_flag below then marks the KB disabled)
#   - scanners/*/output             : every past scan result shown in the UI
#   - tooling/deploy/single-host    : the operator's .env and TLS cert material,
#     without which deploy.sh cannot run
# Idempotent: a no-op once the old directories are gone. Never clobbers a file
# that already exists at the destination.
_reorg_move_leftovers() {                       # $1 = old dir, $2 = new dir
    local old="$SCRIPT_DIR/$1" new="$SCRIPT_DIR/$2" rel dest src
    [[ -d "$old" ]] || return 0
    # Fast path: destination absent -> one atomic rename (preserves ownership of
    # root-owned trees such as knowledge_base/data written by a container).
    if [[ ! -e "$new" ]]; then
        mkdir -p "$(dirname "$new")" 2>/dev/null || true
        if mv "$old" "$new" 2>/dev/null; then
            _REORG_MOVED=$((_REORG_MOVED + 1)); return 0
        fi
    fi
    while IFS= read -r -d '' src; do
        rel="${src#"$old"/}"
        dest="$new/$rel"
        [[ -e "$dest" ]] && continue
        mkdir -p "$(dirname "$dest")" 2>/dev/null || { _REORG_FAILED+=("$1/$rel"); continue; }
        if mv "$src" "$dest" 2>/dev/null; then
            _REORG_MOVED=$((_REORG_MOVED + 1))
        else
            _REORG_FAILED+=("$1/$rel")
        fi
    done < <(find "$old" -mindepth 1 \( -type f -o -type l \) -print0 2>/dev/null)
    find "$old" -mindepth 1 -type d -empty -delete 2>/dev/null || true
    rmdir "$old" 2>/dev/null || true
}

_migrate_reorg_layout() {
    # Cheap guard: nothing to do unless a pre-reorg directory is still present.
    local probe found=0
    for probe in knowledge_base gvm_scan github_secret_hunt trufflehog_scan \
                 supply_chain_scan supply_chain_common supply_chain_analyzer \
                 ai_attack_surface_scan capture_proxy baddns_scan codefix_sandbox \
                 wcvs docker_broker postgres_db deploy scripts hooks e2e \
                 guinea_pigs readmes assets internal validation-benchmarks; do
        [[ -d "$SCRIPT_DIR/$probe" ]] && { found=1; break; }
    done
    [[ "$found" -eq 1 ]] || return 0

    _REORG_MOVED=0
    _REORG_FAILED=()
    info "Migrating pre-6.9 directory layout (moving your data to the new paths)..."

    local pair
    for pair in \
        "knowledge_base:services/knowledge_base" \
        "docker_broker:services/docker_broker" \
        "postgres_db:services/postgres_db" \
        "ai_attack_surface_scan:scanners/ai_attack_surface_scan" \
        "baddns_scan:scanners/baddns_scan" \
        "capture_proxy:scanners/capture_proxy" \
        "codefix_sandbox:scanners/codefix_sandbox" \
        "github_secret_hunt:scanners/github_secret_hunt" \
        "gvm_scan:scanners/gvm_scan" \
        "trufflehog_scan:scanners/trufflehog_scan" \
        "wcvs:scanners/wcvs" \
        "supply_chain_analyzer:scanners/supply_chain_analyzer" \
        "supply_chain_common:scanners/supply_chain_common" \
        "supply_chain_scan:scanners/supply_chain_scan" \
        "e2e:testing/e2e" \
        "guinea_pigs:testing/guinea_pigs" \
        "scripts:tooling/scripts" \
        "hooks:tooling/hooks" \
        "deploy:tooling/deploy" \
        "readmes:docs/readmes" \
        "assets:docs/assets" \
        "internal:_local/internal" \
        "validation-benchmarks:_local/validation-benchmarks" \
    ; do
        _reorg_move_leftovers "${pair%%:*}" "${pair##*:}"
    done

    if [[ "${#_REORG_FAILED[@]}" -gt 0 ]]; then
        warn "Could not move ${#_REORG_FAILED[@]} file(s) (permission denied):"
        printf '    %s\n' "${_REORG_FAILED[@]:0:5}"
        [[ "${#_REORG_FAILED[@]}" -gt 5 ]] && echo "    ... and $(( ${#_REORG_FAILED[@]} - 5 )) more"
        echo ""
        echo "  They are container-written (root-owned). Finish the move with:"
        echo "    sudo ./redamon.sh migrate-layout"
        echo ""
    elif [[ "$_REORG_MOVED" -gt 0 ]]; then
        success "Layout migration complete ($_REORG_MOVED item(s) moved to the new paths)."
    fi
}

# One-time migration from the legacy `.skipkbase` flag (RedAmon <=4.9.3) to the
# new explicit flag pair (`.kbase-enabled` / `.kbase-disabled`). cmd_install
# always writes one of the two markers so the user's explicit choice is sticky
# across `clean` (which keeps KB data on disk). Behavior per case:
#   - .kbase-enabled or .kbase-disabled exists → already migrated → no-op
#   - .skipkbase exists                        → legacy default install (KB off) → convert to .kbase-disabled
#   - no markers, FAISS index on disk          → legacy --kbase install (KB on)  → create .kbase-enabled
#   - no markers, no data                      → fresh clone → create .kbase-disabled (README default)
# Called from every command except cmd_install (which sets the markers explicitly).
_migrate_legacy_kbase_flag() {
    if [[ -f "$KBASE_FLAG_FILE" || -f "$KBASE_DISABLED_FLAG_FILE" ]]; then
        rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
        return
    fi
    if [[ -f "$LEGACY_SKIPKBASE_FLAG_FILE" ]]; then
        rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
        touch "$KBASE_DISABLED_FLAG_FILE"
        return
    fi
    if [[ -s "$SCRIPT_DIR/services/knowledge_base/data/index.faiss" ]]; then
        touch "$KBASE_FLAG_FILE"
    else
        touch "$KBASE_DISABLED_FLAG_FILE"
    fi
}

check_prerequisites() {
    local missing=0

    if ! command -v docker &>/dev/null; then
        error "Docker is not installed. See: https://docs.docker.com/get-docker/"
        missing=1
    fi

    if ! docker compose version &>/dev/null; then
        error "Docker Compose v2 is not installed. See: https://docs.docker.com/compose/install/"
        missing=1
    fi

    if ! command -v git &>/dev/null; then
        error "Git is not installed."
        missing=1
    fi

    if [[ $missing -eq 1 ]]; then
        exit 1
    fi
}

export_version() {
    export REDAMON_VERSION
    REDAMON_VERSION="$(get_version)"
}

# Restore any RUNTIME_TRACKED_PATHS the running stack has rewritten, so the
# `git pull --ff-only` in `update` is not blocked by a file the user never
# touched. Skips paths that are no longer tracked (the marker files are being
# untracked release by release), so this is also the migration path for users
# on an older version where they still are.
_restore_runtime_tracked_files() {
    local p unrestorable=()
    for p in $RUNTIME_TRACKED_PATHS; do
        git -C "$SCRIPT_DIR" ls-files --error-unmatch -- "$p" &>/dev/null || continue
        git -C "$SCRIPT_DIR" diff --quiet -- "$p" 2>/dev/null && continue
        info "Restoring runtime-written file so the update can pull: $p"
        git -C "$SCRIPT_DIR" checkout -- "$p" 2>/dev/null && continue
        unrestorable+=("$p")
    done
    [[ ${#unrestorable[@]} -eq 0 ]] && return 0

    # Swallowing this (the old `|| true`) sent the user straight back to the pull
    # error with nothing they could act on: a scan container creates these paths
    # as root inside a user-owned checkout, so neither git nor the user can
    # replace the file, and `git checkout --` fails silently.
    error "Could not restore runtime-written path(s) - not writable by $(id -un):"
    printf '    %s\n' "${unrestorable[@]}"
    echo ""
    echo "  A scan container created them as root inside your checkout. git cannot"
    echo "  replace them either, so the pull would fail next. Fix:"
    echo "    sudo chown -R \"\$(id -un):\$(id -gn)\" \"$SCRIPT_DIR\""
    exit 1
}

# Tracked files under RUNTIME_TRACKED_PATHS that this user cannot write. They are
# clean today only because the container happened to rewrite identical bytes; the
# first release that changes one makes `git pull` fail with "unable to unlink".
# Warn rather than abort - nothing is broken yet, and an update that would
# otherwise succeed must not be blocked by a latent problem.
_warn_root_owned_runtime_files() {
    local p f offenders=()
    for p in $RUNTIME_TRACKED_PATHS; do
        while IFS= read -r f; do
            [[ -n "$f" && -e "$SCRIPT_DIR/$f" && ! -w "$SCRIPT_DIR/$f" ]] && offenders+=("$f")
        done < <(git -C "$SCRIPT_DIR" ls-files -- "$p" 2>/dev/null)
    done
    [[ ${#offenders[@]} -eq 0 ]] && return 0
    warn "Runtime data file(s) in this checkout are owned by root, not $(id -un):"
    printf '    %s\n' "${offenders[@]}"
    warn "  A future release that changes one of them will fail to pull. Fix now with:"
    warn "    sudo chown -R \"\$(id -un):\$(id -gn)\" \"$SCRIPT_DIR\""
}

# The ref `update` pulls from: the branch's own upstream when it has one, else
# origin/master (what a plain `git clone` of RedAmon leaves you on). Empty output
# + rc 1 when neither exists, which is a legitimate state for an archive install.
_upstream_ref() {
    local u
    u="$(git -C "$SCRIPT_DIR" rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null)" || u=""
    if [[ -n "$u" ]]; then echo "$u"; return 0; fi
    if git -C "$SCRIPT_DIR" rev-parse --verify --quiet origin/master >/dev/null 2>&1; then
        echo "origin/master"; return 0
    fi
    return 1
}

# Tracked files modified in the working tree (never untracked ones - a user's
# stray notes.txt must not read as "you have edits blocking the update").
_dirty_tracked_files() {
    git -C "$SCRIPT_DIR" status --porcelain --untracked-files=no 2>/dev/null
}

# True when this checkout has commits the upstream does not, which is the ONE
# state `pull --ff-only` can never recover from on its own.
_has_local_only_commits() {
    local upstream="$1" n
    n="$(git -C "$SCRIPT_DIR" rev-list --count "$upstream..HEAD" 2>/dev/null)" || return 1
    [[ "${n:-0}" -gt 0 ]]
}

# Does one repo-relative path belong to a RUNTIME_TRACKED_PATH? This single
# decision is what ultimately authorises `reset --hard`, so it lives on its own
# and is asserted directly - a test that reimplements it proves nothing.
#
# The traversal rejection is unreachable through `git diff` output (git refuses
# "." and ".." as tree entries) and is kept anyway: a destructive gate must not
# depend on an invariant enforced somewhere else.
_is_runtime_tracked_path() {
    local f="$1" p
    case "/$f/" in */../*|*/./*) return 1 ;; esac
    for p in $RUNTIME_TRACKED_PATHS; do
        [[ "$f" == "$p" || "$f" == "$p"/* ]] && return 0
    done
    return 1
}

# True when every file those local-only commits touch is a RUNTIME_TRACKED_PATH.
#
# Such commits are RedAmon's own runtime scribbles, committed because a previous
# release's error message literally told users to `git commit -am 'local changes'`
# (issue #185) - advice that converted a self-healing dirty tree into a permanent
# fast-forward dead end. Discarding them loses nothing the next scan will not
# rewrite. Anything else is a real edit and is NEVER reset automatically.
_diverged_by_runtime_scribbles_only() {
    local upstream="$1" files f
    files="$(git -C "$SCRIPT_DIR" diff --name-only "${upstream}...HEAD" 2>/dev/null)" || return 1
    [[ -n "$files" ]] || return 1
    while IFS= read -r f; do
        [[ -n "$f" ]] || continue
        _is_runtime_tracked_path "$f" || return 1
    done <<< "$files"
    return 0
}

# Refuse to run a half-privileged update. `sudo ./redamon.sh install` (or the
# `sudo git commit` the old error message provoked) leaves root-owned files in a
# user-owned checkout; the next non-root run then fails PIECEMEAL - git cannot
# rewrite .git/index, _gpu_export_env cannot write .torch-variant - and the user
# is left on a partially applied update with three unrelated-looking errors.
_assert_checkout_writable() {
    local unwritable=() p
    for p in "$SCRIPT_DIR" "$SCRIPT_DIR/.git" "$SCRIPT_DIR/.git/index" "$TORCH_VARIANT_MARKER"; do
        [[ -e "$p" ]] || continue
        [[ -w "$p" ]] || unwritable+=("$p")
    done
    [[ ${#unwritable[@]} -eq 0 ]] && return 0
    error "This checkout has files the current user ($(id -un)) cannot write:"
    printf '    %s\n' "${unwritable[@]}"
    echo ""
    echo "  They were almost certainly created by an earlier 'sudo ./redamon.sh ...'"
    echo "  or 'sudo git ...'. RedAmon does not need root for its own files. Fix:"
    echo "    sudo chown -R \"\$(id -un):\$(id -gn)\" \"$SCRIPT_DIR\""
    echo "  then re-run WITHOUT sudo:  ./redamon.sh update"
    exit 1
}

# Say so when `git status` itself failed. This matters twice over: it is why the
# auto-heal refused, AND it means any `reset --hard` we suggest could destroy
# uncommitted work sitting in a tree neither we nor the user can currently see.
_warn_unreadable_tree() {
    [[ "$1" == true ]] && return 0
    echo ""
    echo "  NOTE: 'git status' failed here, so your working tree could not be read."
    echo "  A stale .git/index.lock from an interrupted git command is the usual cause;"
    echo "  remove it only if no other git process is running. Until status works,"
    echo "  do NOT run 'reset --hard' - it would discard uncommitted work you cannot see."
    return 0
}

# Bring the checkout onto the newest upstream commit, or explain precisely why it
# cannot be done - the two are not the same failure and the old handler conflated
# them. `pull --ff-only` refuses for three unrelated reasons and every one of them
# was reported as "the working tree has local changes", including the diverged
# case where `git status` is provably empty and that sentence is simply false.
#
# Returns 0 with the checkout fast-forwarded. Exits 1 when only the user can
# resolve it (never returns in that case).
_update_pull() {
    local out upstream dirty

    if out="$(git -C "$SCRIPT_DIR" pull --ff-only 2>&1)"; then return 0; fi
    if out="$(git -C "$SCRIPT_DIR" pull --ff-only origin master 2>&1)"; then return 0; fi

    # Both attempts also FETCHED, so the remote-tracking ref is current here even
    # though the merge was refused - the state checks below see the real gap.
    if ! upstream="$(_upstream_ref)"; then
        error "Could not pull updates: this checkout has no upstream to pull from."
        echo ""
        echo "  git said:"
        printf '%s\n' "$out" | sed 's/^/    /'
        echo ""
        echo "  A RedAmon installed by downloading a zip has no git remote. Re-install"
        echo "  from a clone instead:  git clone https://github.com/samugit83/redamon.git"
        exit 1
    fi

    # A bare `dirty="$(_dirty_tracked_files)"` aborts this whole function under
    # redamon.sh's own `set -euo pipefail` the moment git status fails - exit 128,
    # no output at all, update dead before it says anything. And git status really
    # does fail while refs still resolve: a corrupt index, or another git process
    # holding .git/index.lock while status refreshes it. Capture the status
    # separately, because "cannot tell" is NOT "clean" and must never authorise
    # the destructive reset below.
    local dirty_known=true
    if ! dirty="$(_dirty_tracked_files)"; then
        dirty=""
        dirty_known=false
    fi

    if _has_local_only_commits "$upstream"; then
        # Self-heal the case a previous release actively caused: commits that
        # contain nothing but runtime-written files.
        if [[ -n "${REDAMON_NO_AUTO_RESET:-}" ]] && _diverged_by_runtime_scribbles_only "$upstream"; then
            warn "Diverged by runtime files only, but REDAMON_NO_AUTO_RESET is set."
            warn "  Not touching your history. Recover by hand when you are ready:"
            warn "    git -C \"$SCRIPT_DIR\" reset --hard $upstream"
            exit 1
        fi
        if [[ "$dirty_known" == true && -z "$dirty" ]] && _diverged_by_runtime_scribbles_only "$upstream"; then
            # cmd_update maps changed files -> services by diffing old_head..HEAD.
            # old_head is about to become unreachable AND it contains the scribble,
            # so that diff would list the reverted runtime paths, rebuild images the
            # release never touched, and arm the 40 GB disk gate. Hand back the real
            # pre-divergence base instead.
            UPDATE_BASE_HEAD="$(git -C "$SCRIPT_DIR" merge-base HEAD "$upstream" 2>/dev/null || true)"
            warn "This checkout has local commit(s) containing ONLY files RedAmon writes"
            warn "  at runtime (the MITRE database refreshed by scans). An older version's"
            warn "  error message told you to commit those; that is what blocked the update."
            info "Discarding them and resetting to $upstream (no user edits are affected)."
            if ! git -C "$SCRIPT_DIR" reset --hard "$upstream" >/dev/null 2>&1; then
                error "Could not reset to $upstream. Run it yourself:"
                echo "    git -C \"$SCRIPT_DIR\" reset --hard $upstream"
                exit 1
            fi
            success "Recovered: the checkout is back on $upstream."
            return 0
        fi

        error "Could not pull updates: this checkout has commits that $upstream does not."
        echo ""
        echo "  Local-only commits:"
        git -C "$SCRIPT_DIR" log --oneline "$upstream..HEAD" 2>/dev/null | head -20 \
            | while IFS= read -r line; do echo "    $line"; done
        echo ""
        echo "  A fast-forward can never resolve this. Choose one:"
        echo ""
        echo "  If those commits are NOT yours (RedAmon runtime files you were once"
        echo "  told to commit), discard them:"
        echo "    git -C \"$SCRIPT_DIR\" reset --hard $upstream   # destructive"
        echo ""
        echo "  If they ARE your work, keep it on a branch, then update:"
        echo "    git -C \"$SCRIPT_DIR\" branch my-changes"
        echo "    git -C \"$SCRIPT_DIR\" reset --hard $upstream"
        echo "    ./redamon.sh update"
        _warn_unreadable_tree "$dirty_known"
        exit 1
    fi

    if [[ "$dirty_known" == true && -n "$dirty" ]]; then
        error "Could not pull updates: the working tree has local changes."
        echo ""
        echo "  Modified files:"
        printf '%s\n' "$dirty" | head -20 | while IFS= read -r line; do echo "    $line"; done
        echo ""
        echo "  If those are NOT your edits, discard them and re-run:"
        echo "    git -C \"$SCRIPT_DIR\" checkout -- <file>     # one file"
        echo "    git -C \"$SCRIPT_DIR\" checkout -- .          # all of them (destructive)"
        echo ""
        echo "  If they ARE your edits, set them aside first:"
        echo "    git -C \"$SCRIPT_DIR\" stash && ./redamon.sh update && git -C \"$SCRIPT_DIR\" stash pop"
        echo ""
        echo "  Do NOT 'git commit' them: that diverges your copy from the project and"
        echo "  no future update can fast-forward past it."
        exit 1
    fi

    # Clean tree, no local commits, still refused: network, auth or a detached
    # HEAD. Nothing to guess at - show what git actually said.
    error "Could not pull updates."
    _warn_unreadable_tree "$dirty_known"
    echo ""
    echo "  git said:"
    printf '%s\n' "$out" | sed 's/^/    /'
    exit 1
}

# Repair data-volume ownership for the non-root webapp (uid 1001 nextjs).
#
# A named volume only inherits ownership from the image when Docker CREATES it
# empty AND the image pre-created the mountpoint. /data/supply-chain-uploads was
# missing from webapp/Dockerfile, so Docker made it root:root and every L1
# SBOM upload failed with:
#   EACCES: permission denied, mkdir '/data/supply-chain-uploads/<project>'
# which the UI showed only as "Failed to upload file".
#
# The Dockerfile now pre-creates it, but that ONLY helps a volume that does not
# exist yet - an existing install keeps the root-owned volume forever. So repair
# it here, idempotently, on every install/update/up.
# Every ecosystem the offline OSV DB can hold. MUST stay in step with
# scanners/supply_chain_common/osv_db_sync.py SEED_MANIFESTS and the orchestrator's
# _OSV_SYNC_ECOSYSTEMS.
OSV_ALL_ECOSYSTEMS="npm PyPI Go Maven crates.io Packagist RubyGems NuGet"

# Populate the offline OSV database so supply-chain scans actually have data.
#
# This used to be entirely manual. A scan against an un-synced ecosystem could
# not verdict anything and reported "offline OSV database has no 'PyPI'
# ecosystem(s)" - correct, but it meant every operator had to discover the
# supply-chain-sync subcommand before the feature did anything useful.
#
# Cheap to call repeatedly: the sync is TTL-marked per ecosystem and skips any
# that are already fresh, so this is a no-op after the first run.
#
# Best-effort by design: it downloads ~279 MB on a cold install and MUST NOT
# fail install/update if the network is unavailable. The scan-time guard still
# reports an actionable error if an ecosystem is missing.
ensure_sca_intel() {
    # Supply-chain incident catalog (~5 MB). Best-effort, exactly like the OSV
    # database above.
    #
    # Why this runs here at all, given the orchestrator refreshes the catalog on
    # the scan-spawn path: that refresh only fires when a SCAN starts. Captured
    # traffic (A1) does not need a scan - an operator using only the AI agent
    # with HTTP Traffic Capture on would never trigger one, so the catalog would
    # stay empty and every captured request would silently read as "no match".
    # Seeding it here closes that hole and costs one 5 MB fetch.
    if [[ "$(_env_get SCA_INTEL_AUTO_REFRESH "$SCRIPT_DIR/.env")" == "false" ]]; then
        info "SCA_INTEL_AUTO_REFRESH=false; skipping the supply-chain incident catalog (air-gapped)"
        return 0
    fi
    if ! docker image inspect redamon-supply-chain-analyzer:latest &>/dev/null; then
        warn "Analyzer image not built yet; skipping incident catalog (run './redamon.sh sca-intel-sync' after the build)"
        return 0
    fi
    info "Ensuring supply-chain incident catalog"
    # SUBSHELL for the same reason as ensure_osv_db: cmd_sca_intel_sync exits 1
    # on failure, and a bare `|| warn` cannot catch an exit - it would abort the
    # whole install/update. A missing catalog must degrade to "did not run",
    # never stop the stack coming up.
    ( cmd_sca_intel_sync ) || warn "Incident catalog sync incomplete; supply-chain findings will carry no incident context until './redamon.sh sca-intel-sync' succeeds. This is not a problem: RedAmon runs normally with the sync off, you just won't see incident context on supply-chain findings."
}

ensure_osv_db() {
    local ecos="${OSV_DB_ECOSYSTEMS:-$(_env_get OSV_DB_ECOSYSTEMS "$SCRIPT_DIR/.env")}"
    ecos="${ecos:-$OSV_ALL_ECOSYSTEMS}"
    ecos="${ecos//,/ }"
    if ! docker image inspect redamon-supply-chain-analyzer:latest &>/dev/null; then
        # cmd_supply_chain_sync builds it on demand, so this is only reachable
        # when the caller runs before any image exists. Say so rather than
        # skipping in silence - an empty OSV DB makes every supply-chain scan
        # report a missing ecosystem.
        warn "Analyzer image not built yet; skipping OSV database sync (run './redamon.sh supply-chain-sync' after the build)"
        return 0
    fi
    info "Ensuring offline OSV database (${ecos})"
    # SUBSHELL on purpose: cmd_supply_chain_sync calls `exit 1` when the
    # analyzer build or the download fails, and a bare `|| warn` does NOT catch
    # an exit - it would abort the entire install/update. Containing it in a
    # subshell keeps this step genuinely best-effort, which is the whole point:
    # a missing OSV database degrades supply-chain scanning to an actionable
    # error, it must never stop the stack from coming up.
    # shellcheck disable=SC2086
    ( cmd_supply_chain_sync $ecos ) || warn "OSV database sync incomplete; supply-chain scans will report which ecosystems are missing"
}

ensure_volume_ownership() {
    local vol="redamon_supply_chain_uploads"
    docker volume inspect "$vol" >/dev/null 2>&1 || return 0
    # Cheap no-op when already correct; only chown when it is not.
    if docker run --rm -u root -v "$vol":/d alpine \
         sh -c '[ "$(stat -c %u /d)" = "1001" ]' >/dev/null 2>&1; then
        return 0
    fi
    info "Repairing ownership of $vol (webapp runs as uid 1001)"
    docker run --rm -u root -v "$vol":/d alpine chown -R 1001:1001 /d >/dev/null 2>&1 \
        || warn "Could not repair $vol ownership; SBOM uploads may fail"
}

ensure_auth_secrets() {
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"
    if ! grep -q '^AUTH_SECRET=' "$env_file" 2>/dev/null; then
        echo "AUTH_SECRET=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated AUTH_SECRET"
    fi
    if ! grep -q '^INTERNAL_API_KEY=' "$env_file" 2>/dev/null; then
        echo "INTERNAL_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated INTERNAL_API_KEY"
    fi
    # S3/E6: least-privilege token injected into scan containers INSTEAD of the
    # master INTERNAL_API_KEY. Scoped (webapp) to settings/projects GET + agent
    # /llm/*; cannot mint admins or harvest LLM-provider keys.
    if ! grep -q '^SCANNER_API_KEY=' "$env_file" 2>/dev/null; then
        echo "SCANNER_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated SCANNER_API_KEY"
    fi
    if ! grep -q '^ORCHESTRATOR_API_KEY=' "$env_file" 2>/dev/null; then
        echo "ORCHESTRATOR_API_KEY=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated ORCHESTRATOR_API_KEY"
    fi
    # Shared bearer token the agent presents to the Kali MCP servers and the
    # servers validate on every inbound SSE request (STRIDE S10 defense-in-depth).
    # Stateless (not baked into any volume), so append-if-absent is safe.
    if ! grep -q '^MCP_AUTH_TOKEN=' "$env_file" 2>/dev/null; then
        echo "MCP_AUTH_TOKEN=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated MCP_AUTH_TOKEN"
    fi
    # Dedicated secret the webapp uses to sign short-lived agent-WebSocket tickets
    # and the agent verifies on the /ws/agent init frame (STRIDE S6). Kept SEPARATE
    # from AUTH_SECRET so an agent compromise cannot forge login cookies. Stateless.
    if ! grep -q '^AGENT_WS_TICKET_SECRET=' "$env_file" 2>/dev/null; then
        echo "AGENT_WS_TICKET_SECRET=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated AGENT_WS_TICKET_SECRET"
    fi
    # Inbound token the tunnel-manager (:8015) validates on config pushes, and the
    # webapp presents when pushing tunnel config (STRIDE I19/S14). Inbound-validation
    # only (same category as MCP_AUTH_TOKEN), so the worker holding it does not
    # violate the "worker holds no secrets" rule. Stateless.
    if ! grep -q '^TUNNEL_AUTH_TOKEN=' "$env_file" 2>/dev/null; then
        echo "TUNNEL_AUTH_TOKEN=$(openssl rand -hex 32)" >> "$env_file"
        info "Generated TUNNEL_AUTH_TOKEN"
    fi
    # Scoped INSERT-only DSN for the HTTP-traffic-capture ingest worker. This is the
    # SINGLE SOURCE OF TRUTH for the traffic_ingest password: the webapp entrypoint
    # (scripts/apply-ingest-role.mjs) provisions the matching Postgres role from it
    # on every boot, and the orchestrator hands it to the spawned ingest container.
    # Without it the ingest gets an EMPTY DSN and every captured request is silently
    # dropped. Append-if-absent + hex password (URL/SQL-safe, no encoding needed).
    if ! grep -q '^TRAFFIC_INGEST_DATABASE_URL=' "$env_file" 2>/dev/null; then
        local _ti_db
        _ti_db="$(_env_get POSTGRES_DB "$env_file")"
        _ti_db="${_ti_db:-redamon}"
        echo "TRAFFIC_INGEST_DATABASE_URL=postgresql://traffic_ingest:$(openssl rand -hex 32)@postgres:5432/${_ti_db}" >> "$env_file"
        info "Generated TRAFFIC_INGEST_DATABASE_URL (capture ingest role)"
    fi
}

# Compose project name (used to resolve the data-volume names). Must match
# docker compose's own derivation or ensure_db_secrets would mis-detect a fresh
# vs existing install and could regenerate a password against a live DB.
# Precedence mirrors compose: exported COMPOSE_PROJECT_NAME, then the same var in
# .env, then the sanitised working-directory basename.
compose_project_name() {
    if [ -n "${COMPOSE_PROJECT_NAME:-}" ]; then
        echo "$COMPOSE_PROJECT_NAME"
        return
    fi
    local env_file="$SCRIPT_DIR/.env"
    if [ -f "$env_file" ]; then
        local from_env
        from_env="$(_env_get COMPOSE_PROJECT_NAME "$env_file")"
        if [ -n "$from_env" ]; then
            echo "$from_env"
            return
        fi
    fi
    basename "$SCRIPT_DIR" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-'
}

# True (0) if the named docker volume for THIS project already exists.
_data_volume_exists() {
    local suffix="$1"   # e.g. postgres_data
    local project; project="$(compose_project_name)"
    docker volume inspect "${project}_${suffix}" >/dev/null 2>&1
}

# Rotate the LIVE Postgres password from <old> to <new> using the old creds.
# Returns 0 on success, non-zero on failure (wrong old password / DB down), so
# the caller can decide NOT to write .env (avoiding a split-brain). Isolated in
# its own function so the shell test harness can stub docker() around it.
_rotate_postgres_password() {
    local old="$1" new="$2"
    local user db
    user="$(_env_get POSTGRES_USER)"
    db="$(_env_get POSTGRES_DB)"
    user="${user:-redamon}"
    db="${db:-redamon}"
    docker exec -e "PGPASSWORD=${old}" redamon-postgres \
        psql -U "$user" -d "$db" -v ON_ERROR_STOP=1 \
        -c "ALTER USER \"${user}\" WITH PASSWORD '${new}';" >/dev/null 2>&1
}

# Rotate the LIVE Neo4j password from <old> to <new>. neo4j:5.26-community only
# supports the SELF-SERVICE form (ALTER CURRENT USER ... FROM ... TO ...); the
# admin form (ALTER USER neo4j SET PASSWORD) is Enterprise-only and is rejected
# on Community. On an already-initialised volume Neo4j ignores NEO4J_AUTH, so
# this cypher-shell rotation is the only effective path. Returns 0 on success.
_rotate_neo4j_password() {
    local old="$1" new="$2"
    docker exec redamon-neo4j \
        cypher-shell -u neo4j -p "$old" \
        "ALTER CURRENT USER SET PASSWORD FROM '${old}' TO '${new}';" >/dev/null 2>&1
}

# Set the GVM/OpenVAS gvmd 'admin' user's password to <new>. Unlike Postgres and
# Neo4j, gvmd's admin form needs NO old password: `gvmd --user=admin
# --new-password` resets it unconditionally, so this is naturally idempotent and
# works whether the gvmd_data volume is still on the community image's admin/admin
# default or on a value a prior run already set. Must run inside the gvmd
# container as the gvmd user. Returns 0 on success. (See ensure_gvm_secret /
# reconcile_gvm_admin_password for the two-phase generate-then-apply flow.)
_rotate_gvm_admin_password() {
    local new="$1"
    docker exec -u gvmd redamon-gvm-gvmd \
        gvmd --user=admin --new-password="$new" >/dev/null 2>&1
}

# True iff `password` authenticates against the running Neo4j.
_neo4j_auth_ok() {
    docker exec redamon-neo4j cypher-shell -u neo4j -p "$1" 'RETURN 1;' >/dev/null 2>&1
}

# S13 / #160: the password Neo4j baked into its volume at first init is the ONLY
# one that works; NEO4J_AUTH is ignored once the volume exists. A .env value that
# was hand-set (the #155 work-around) or left over from a stale volume can disagree
# with it, and ensure_db_secrets trusts a pinned .env without checking -- so the
# mismatch only surfaces LATER as a cryptic `AuthenticationRateLimit` in the recon
# pipeline. Here we VERIFY the pinned password and auto-reconcile: clear any auth
# rate-limit (repeated wrong-password attempts lock out even the correct one), then
# rotate the volume TO the .env value using a known old password. If we cannot, we
# stop with rotate-or-wipe steps instead of handing over a silently-broken stack.
# Best-effort + fail-safe: if Neo4j will not come up we return 0 (never block a start
# on this check). Returns 1 only on a confirmed, un-reconcilable mismatch.
_reconcile_neo4j_password() {
    local envpw="$1"
    [[ -z "$envpw" ]] && return 0

    # Need Neo4j running to probe. .env already carries the password so the
    # fail-closed compose `:?` resolves; start it idempotently if it is down.
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        docker compose up -d neo4j >/dev/null 2>&1 || return 0
    fi
    _kb_wait_neo4j >/dev/null 2>&1 || return 0   # cannot verify -> do not block

    _neo4j_auth_ok "$envpw" && return 0

    warn "Neo4j did not accept NEO4J_PASSWORD from .env; clearing any auth rate-limit..."
    docker restart redamon-neo4j >/dev/null 2>&1
    _kb_wait_neo4j >/dev/null 2>&1 || true
    if _neo4j_auth_ok "$envpw"; then
        success "Neo4j auth OK after clearing the rate-limit."
        return 0
    fi

    # Genuine mismatch: try known old passwords, rotate the volume to the .env value.
    local cand
    for cand in "$(_env_get NEO4J_PASSWORD_OLD)" changeme123; do
        [[ -z "$cand" ]] && continue
        if _neo4j_auth_ok "$cand"; then
            info "Neo4j volume password differs from .env; rotating it to match .env..."
            if _rotate_neo4j_password "$cand" "$envpw" && _neo4j_auth_ok "$envpw"; then
                success "Reconciled: Neo4j now uses NEO4J_PASSWORD from .env."
                return 0
            fi
        fi
    done
    return 1
}

# Harden the datastore passwords (STRIDE S13/S1). The passwords are baked into
# the postgres/neo4j data volumes at FIRST init, so on a FRESH install (volume
# absent) we auto-generate before the volume is created. On an EXISTING install
# still on the compose default we now ROTATE in place: ALTER the live DB with the
# old (default) creds FIRST, and only on success write the new value to .env, so
# .env and the volume never disagree. If the ALTER fails we fall back to the old
# warn-only behaviour (fail-safe: never a locked-out DB).
# Uses url/shell-safe hex so DATABASE_URL and NEO4J_AUTH need no escaping.
# S13: rotation ALTERs the LIVE DB, so the DB container must be RUNNING. On a
# STOPPED default-cred stack (the reboot -> `up` path, or `down && update`) the DB
# is down AND the fail-closed compose `${VAR:?}` refuses to start it because .env
# has no password yet -- a chicken-and-egg that would abort `up`/`update`/`dev`
# with a cryptic "required variable ... is missing a value". This brings the
# needed DB(s) up with their OLD default creds (exported ONLY for this one call so
# the `:?` interpolation resolves; an already-initialised volume ignores the
# value), so the subsequent ALTER can run and ensure_db_secrets can pin the new
# value. Best-effort: on any failure ensure_db_secrets falls back to warn-only.
_start_dbs_for_rotation_if_needed() {
    local env_file="$SCRIPT_DIR/.env"
    local svcs=() need=false
    if ! grep -q '^POSTGRES_PASSWORD=' "$env_file" 2>/dev/null \
         && _data_volume_exists postgres_data \
         && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-postgres$'; then
        svcs+=(postgres); need=true
    fi
    if ! grep -q '^NEO4J_PASSWORD=' "$env_file" 2>/dev/null \
         && _data_volume_exists neo4j_data \
         && ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        svcs+=(neo4j); need=true
    fi
    [[ "$need" == false ]] && return 0

    info "Starting ${svcs[*]} on current default creds so S13 can rotate the password..."
    # compose interpolates the WHOLE file, so BOTH `:?` vars must resolve even to
    # start one service; supply both defaults for this single command only. These
    # match the compose defaults and the `specs` below; an init'd volume ignores
    # them, so the container comes up on the volume's real (default) password.
    if ! POSTGRES_PASSWORD=redamon_secret NEO4J_PASSWORD=changeme123 \
            docker compose up -d "${svcs[@]}" >/dev/null 2>&1; then
        warn "Could not start ${svcs[*]} for rotation; falling back to warn-only fail-safe."
        return 0
    fi
    local c waited
    for c in "${svcs[@]}"; do
        waited=0
        while [[ $waited -lt 60 ]]; do
            [[ "$(docker inspect --format='{{.State.Health.Status}}' "redamon-$c" 2>/dev/null || echo x)" == "healthy" ]] && break
            sleep 2; waited=$((waited + 2))
        done
    done
}

ensure_db_secrets() {
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"

    # If a default-cred volume needs rotating but its DB is down, bring it up
    # first (see helper) so the live ALTER below can run. No-op on fresh installs
    # (no volume) and on already-pinned / already-running stacks.
    _start_dbs_for_rotation_if_needed

    # (var, volume suffix, compose default, rotate-fn) tuples.
    local specs=(
        "POSTGRES_PASSWORD:postgres_data:redamon_secret:_rotate_postgres_password"
        "NEO4J_PASSWORD:neo4j_data:changeme123:_rotate_neo4j_password"
    )

    local project; project="$(compose_project_name)"
    local spec var suffix default rotate_fn old new
    # Vars we could NOT establish because a data volume exists but rotation off
    # the default failed. Collected here so we can STOP with one actionable
    # message instead of silently leaving .env without a password (#155).
    local -a unresolved=()
    for spec in "${specs[@]}"; do
        var="$(echo "$spec" | cut -d: -f1)"
        suffix="$(echo "$spec" | cut -d: -f2)"
        default="$(echo "$spec" | cut -d: -f3)"
        rotate_fn="$(echo "$spec" | cut -d: -f4)"

        # Operator/prior-run already pinned it in .env. Respect the value, but for
        # Neo4j VERIFY it actually matches the volume and reconcile if not (#160): a
        # hand-set password that disagrees with the baked-in volume password
        # otherwise fails later with a cryptic AuthenticationRateLimit. On a
        # confirmed, un-reconcilable mismatch, fall through to the actionable stop.
        if grep -q "^${var}=" "$env_file" 2>/dev/null; then
            if [[ "$var" == "NEO4J_PASSWORD" ]] && _data_volume_exists "$suffix" \
               && ! _reconcile_neo4j_password "$(_env_get NEO4J_PASSWORD)"; then
                unresolved+=("${var}=${project}_${suffix}")
            fi
            continue
        fi

        if _data_volume_exists "$suffix"; then
            # Existing DB, initialised with the weak compose default. Rotate the
            # LIVE password using the old default, THEN write the new .env value.
            old="$default"
            new="$(openssl rand -hex 24)"
            info "Rotating ${var} on the existing ${suffix} volume (off the default '${default}')..."
            if "$rotate_fn" "$old" "$new"; then
                echo "${var}=${new}" >> "$env_file"
                info "Rotated ${var} on the live database and pinned it in .env."
            else
                # Rotation failed: DO NOT write .env (a mismatch would lock out
                # consumers / split-brain). But we also must NOT leave .env
                # without the value and press on — the fail-closed compose
                # `${VAR:?}` guard would then abort a later `up`/`update` with a
                # cryptic interpolation error (issue #155). Record it and stop
                # loudly below with remediation steps. The volume is untouched.
                warn "${var} rotation FAILED (wrong old password, or the database is not up)."
                unresolved+=("${var}=${project}_${suffix}")
            fi
        else
            # Fresh install — generate before the DB volume is created so it
            # initialises with the strong value across all consumers.
            echo "${var}=$(openssl rand -hex 24)" >> "$env_file"
            info "Generated strong ${var} (fresh install)"
        fi
    done

    # #155: at least one required DB password could not be set because a stale
    # data volume exists that we could not rotate off the compose default. This
    # is common on re-clone / re-install over Docker volumes that survive repo
    # deletion (e.g. WSL2 + Docker Desktop). Stop here with concrete remediation
    # rather than hand the operator an unstartable stack + a cryptic compose
    # error. Nothing has been destroyed; the volumes are left exactly as they are.
    if (( ${#unresolved[@]} > 0 )); then
        local u vols=() var_names=()
        for u in "${unresolved[@]}"; do
            var_names+=("${u%%=*}")
            vols+=("${u#*=}")
        done
        error "Cannot configure the database password(s): ${var_names[*]}"
        error "A data volume already exists for each, but it was not initialised"
        error "with RedAmon's default credentials, so the password could not be set"
        error "automatically. RedAmon will not start without these (STRIDE S13)."
        echo "" >&2
        echo "  Leftover volume(s): ${vols[*]}" >&2
        echo "" >&2
        echo "  Choose ONE fix, then re-run the same command:" >&2
        echo "" >&2
        echo "  A) The data is disposable (fresh setup / leftover from a prior run)." >&2
        echo "     Remove the stale volume(s) so RedAmon can re-initialise cleanly:" >&2
        echo "         docker volume rm ${vols[*]}" >&2
        echo "" >&2
        echo "  B) You need the data in those volumes: pin each volume's CURRENT" >&2
        echo "     password explicitly in .env (RedAmon then respects it as-is):" >&2
        local vn
        for vn in "${var_names[@]}"; do
            echo "         echo '${vn}=<the volume's existing password>' >> .env" >&2
        done
        echo "" >&2
        exit 1
    fi
}

# GVM/OpenVAS admin credential (STRIDE S13, parity with ensure_db_secrets). The
# community gvmd image auto-creates the 'admin' user with the weak admin/admin
# default on first boot and exposes NO env var to preset it — so, exactly like an
# already-initialised Neo4j volume, the ONLY effective path is to let it boot on
# the default and then rotate. This half runs PRE-`up`: it generates a strong
# GVM_PASSWORD and pins it in .env so the recon-orchestrator (which reads
# GVM_PASSWORD to spawn GVM scan containers, docker-compose.yml) gets the strong
# value the moment it starts; reconcile_gvm_admin_password() applies the same
# value to the live gvmd 'admin' user once gvmd is healthy (POST-`up`). Only acts
# when GVM is enabled; an operator-pinned GVM_PASSWORD is respected. Best-effort:
# a GVM hiccup must never block a core install, so this only ever appends a line.
ensure_gvm_secret() {
    is_gvm_enabled || return 0
    local env_file="$SCRIPT_DIR/.env"
    touch "$env_file"
    if ! grep -q '^GVM_PASSWORD=' "$env_file" 2>/dev/null; then
        echo "GVM_PASSWORD=$(openssl rand -hex 24)" >> "$env_file"
        info "Generated strong GVM_PASSWORD (GVM/OpenVAS admin)"
    fi
}

# POST-`up`: bring the live gvmd 'admin' user in line with GVM_PASSWORD from .env.
# gvmd creates 'admin' only after it boots (and only on a FRESH gvmd_data volume
# is it the admin/admin default), so unlike the DB rotations this cannot run
# pre-`up`; it waits for gvmd's healthcheck, then unconditionally sets the
# password (see _rotate_gvm_admin_password — idempotent, needs no old password).
# Was the deploy-only, print-but-don't-persist gap that left the orchestrator on
# admin/admin while gvmd's password had moved, so every GVM scan failed to
# authenticate. Best-effort + fail-safe: warns and returns 0 (never aborts the
# install) if gvmd never turns healthy or the reset keeps failing, so the core
# stack is never held hostage to GVM. Only acts when GVM is enabled and .env pins
# a GVM_PASSWORD (ensure_gvm_secret guarantees the latter on a --gvm run).
reconcile_gvm_admin_password() {
    is_gvm_enabled || return 0
    local pw; pw="$(_env_get GVM_PASSWORD)"
    [[ -z "$pw" ]] && return 0

    # admin is created early in boot (long before the ~30 min feed sync), so a
    # healthy gvmd is enough — no need to wait out the feeds.
    local waited=0 max=180
    while [[ $waited -lt $max ]]; do
        [[ "$(docker inspect --format='{{.State.Health.Status}}' redamon-gvm-gvmd 2>/dev/null || echo x)" == "healthy" ]] && break
        sleep 2; waited=$((waited + 2))
    done
    if [[ "$(docker inspect --format='{{.State.Health.Status}}' redamon-gvm-gvmd 2>/dev/null || echo x)" != "healthy" ]]; then
        warn "gvmd not healthy yet; GVM admin password not applied from .env."
        warn "Apply later: docker compose exec -u gvmd gvmd gvmd --user=admin --new-password=\"\$(grep '^GVM_PASSWORD=' .env | cut -d= -f2-)\""
        return 0
    fi

    # Even a 'healthy' gvmd can reject the first manage call while its Postgres
    # connection warms up; a short retry covers that window.
    local attempt
    for attempt in 1 2 3 4 5; do
        if _rotate_gvm_admin_password "$pw"; then
            success "GVM admin password set from .env (gvmd 'admin' no longer admin/admin)."
            return 0
        fi
        sleep 3
    done
    warn "Could not set the GVM admin password automatically (gvmd busy)."
    warn "Apply later: docker compose exec -u gvmd gvmd gvmd --user=admin --new-password=\"\$(grep '^GVM_PASSWORD=' .env | cut -d= -f2-)\""
    return 0
}

# S11: minimum admin-password length enforced at creation and reset.
MIN_ADMIN_PASSWORD_LEN=12
_password_strong_enough() {
    local pw="$1"
    [[ ${#pw} -ge $MIN_ADMIN_PASSWORD_LEN ]]
}

# Poll the webapp health endpoint until it answers. Returns 0 once healthy, 1 if
# it never came up within the budget. Default ~3 min (90 * 2s): a heavy first
# boot (--gvm starts the OpenVAS/gvmd feed-sync alongside the webapp and can
# saturate a small VM's CPU/IO for a while) legitimately needs longer than the
# old 60s, which was silently skipping admin creation (issue #156).
_wait_for_webapp() {
    local retries=0 max="${1:-90}"
    while ! docker compose exec -T webapp wget -q --spider http://127.0.0.1:3000/api/health 2>/dev/null; do
        retries=$((retries + 1))
        [[ $retries -ge $max ]] && return 1
        sleep 2
    done
    return 0
}

# True (0) if at least one admin (role=admin with a password) exists.
_admin_exists() {
    local has_admin
    has_admin=$(docker compose exec -T webapp node scripts/check-admin.mjs 2>/dev/null | tr -d '[:space:]')
    [[ -n "$has_admin" && "$has_admin" != "0" ]]
}

# Collect the admin details and upsert via create-admin.mjs. Non-interactive when
# ADMIN_NAME/ADMIN_EMAIL/ADMIN_PASSWORD are all present in the environment (mirrors
# the single-host deploy path); otherwise prompts on the controlling terminal.
# create-admin.mjs upserts on email: a matching email RESETS that admin's
# password, a new email adds another admin — so re-running is safe.
_prompt_and_create_admin() {
    local a_name="${ADMIN_NAME:-}" a_email="${ADMIN_EMAIL:-}" a_pass="${ADMIN_PASSWORD:-}" a_pass2=""
    if [[ -n "$a_name" && -n "$a_email" && -n "$a_pass" ]]; then
        info "Using ADMIN_NAME / ADMIN_EMAIL / ADMIN_PASSWORD from the environment (non-interactive)."
        # S11: enforce the minimum password length here too.
        if ! _password_strong_enough "$a_pass"; then
            error "ADMIN_PASSWORD too short (minimum ${MIN_ADMIN_PASSWORD_LEN} characters)."
            exit 1
        fi
    else
        read -rp "  Admin name: " a_name </dev/tty
        read -rp "  Admin email: " a_email </dev/tty
        while true; do
            read -srp "  Admin password: " a_pass </dev/tty
            echo ""
            read -srp "  Confirm password: " a_pass2 </dev/tty
            echo ""
            if [[ "$a_pass" != "$a_pass2" ]]; then
                warn "Passwords do not match. Try again."
                continue
            fi
            # S11: reject a weak admin password (min length) instead of warning.
            if ! _password_strong_enough "$a_pass"; then
                warn "Password too short (minimum ${MIN_ADMIN_PASSWORD_LEN} characters). Try again."
                continue
            fi
            break
        done
    fi
    docker compose exec -T \
        -e "ADMIN_NAME=$a_name" \
        -e "ADMIN_EMAIL=$a_email" \
        -e "ADMIN_PASSWORD=$a_pass" \
        webapp node scripts/create-admin.mjs
    success "Admin user ready."
    echo ""
}

ensure_admin() {
    if ! _wait_for_webapp; then
        # Do NOT dead-end: point the operator at the standalone recovery command
        # so a slow first boot never leaves them unable to log in (issue #156).
        warn "Webapp is not responding yet -- skipping the automatic admin setup."
        warn "Once it is up (check './redamon.sh status'), create the admin with:"
        warn "    ./redamon.sh create-admin"
        return
    fi

    if ! _admin_exists; then
        echo ""
        warn "No admin user found. Let's create one."
        echo ""
        _prompt_and_create_admin
    fi
}

# Standalone admin (re)creation — the reliable path when the automatic prompt was
# skipped (slow first boot) or the admin password was lost. Safe to re-run: it
# upserts on email (matching email resets the password; new email adds an admin).
cmd_create_admin() {
    print_banner
    check_prerequisites
    if ! _wait_for_webapp 150; then   # ~5 min: this is an explicit, user-driven call
        error "Webapp is not responding at http://localhost:3000/api/health."
        error "Start the stack first ('./redamon.sh up'), then re-run './redamon.sh create-admin'."
        exit 1
    fi
    if _admin_exists; then
        warn "An admin user already exists."
        warn "Continuing will ADD a new admin, or RESET the password if you reuse an existing admin's email."
    else
        info "No admin user found yet — let's create one."
    fi
    echo ""
    _prompt_and_create_admin
}

cmd_reset_password() {
    echo ""
    read -rp "  User email: " EMAIL </dev/tty
    read -srp "  New password: " NEW_PASS </dev/tty
    echo ""
    read -srp "  Confirm password: " CONFIRM </dev/tty
    echo ""

    if [[ "$NEW_PASS" != "$CONFIRM" ]]; then
        error "Passwords do not match."
        exit 1
    fi

    # S11: enforce a minimum password strength on reset too.
    if ! _password_strong_enough "$NEW_PASS"; then
        error "Password too short (minimum ${MIN_ADMIN_PASSWORD_LEN} characters)."
        exit 1
    fi

    docker compose exec -T \
        -e "RESET_EMAIL=$EMAIL" \
        -e "RESET_PASSWORD=$NEW_PASS" \
        webapp node scripts/reset-password.mjs
    success "Password updated."
    echo ""
}

# Wipe the orchestrator-spawned, non-compose-managed containers (AI Attack Surface
# scan containers + the on-demand local LLM). Safe to call anytime — a no-op when
# none are present. Must run BEFORE `compose down --volumes` so the local-llm
# container releases the models volume and it can actually be removed.
remove_spawned_containers() {
    local ids
    ids=$(docker ps -aq "${SPAWNED_CONTAINER_NAME_FILTERS[@]}" 2>/dev/null || true)
    if [[ -n "$ids" ]]; then
        info "Removing orchestrator-spawned AI containers (scan + local LLM)..."
        # shellcheck disable=SC2086
        docker rm -f $ids >/dev/null 2>&1 || true
    fi
}

remove_redamon_images() {
    # Remove locally-built redamon images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep '^redamon-' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove GVM / Greenbone images
    docker images --format '{{.Repository}}:{{.Tag}}' \
        | grep 'registry.community.greenbone.net' \
        | xargs -r docker rmi 2>/dev/null || true

    # Remove ProjectDiscovery + recon tool images (pulled at runtime by entrypoint)
    local runtime_images=(
        "projectdiscovery/naabu"
        "projectdiscovery/httpx"
        "projectdiscovery/katana"
        "projectdiscovery/nuclei"
        "projectdiscovery/subfinder"
        "projectdiscovery/dnsx"
        "projectdiscovery/uncover"
        "sxcurity/gau"
        "caffix/amass"
        "frost19k/puredns"
        "jauderho/hakrawler"
        "trufflesecurity/trufflehog"
        # On-demand local LLM (Ollama) for the AI Attack Surface judge/attacker —
        # pulled at runtime by the orchestrator, not built.
        "$LOCAL_LLM_IMAGE"
    )
    for img in "${runtime_images[@]}"; do
        docker rmi "$img" 2>/dev/null || true
    done
}

pull_gvm_images() {
    # GVM images are large (~250MB each) and can fail with "unexpected EOF"
    # due to a known Docker+Go 1.24 bug (moby/moby#49513) and Greenbone
    # registry instability. Pull individually with retries.
    local max_retries=5
    local gvm_services
    local compose_services
    if ! compose_services=$(docker compose config --services); then
        error "Cannot read Compose configuration for GVM startup."
        return 1
    fi
    gvm_services=$(printf '%s\n' "$compose_services" | grep '^gvm-' || true)

    if [[ -z "$gvm_services" ]]; then
        return 0
    fi

    # Skip pull if all GVM images already exist locally (pass force=true to override)
    local force="${1:-false}"
    if [[ "$force" != "true" ]]; then
        local need_pull=false
        local compose_json
        compose_json=$(docker compose config --format json 2>/dev/null)
        for svc in $gvm_services gvmd; do
            local img
            img=$(echo "$compose_json" | jq -r ".services.\"$svc\".image // empty")
            if [[ -n "$img" ]] && ! docker image inspect "$img" &>/dev/null; then
                need_pull=true
                break
            fi
        done
        if [[ "$need_pull" == "false" ]]; then
            info "GVM images already present locally, skipping pull."
            return 0
        fi
    fi

    info "Pulling GVM images (with retry)..."
    local failed=()
    for svc in $gvm_services; do
        local attempt=1
        while [[ $attempt -le $max_retries ]]; do
            if docker compose pull "$svc" 2>/dev/null; then
                break
            fi
            if [[ $attempt -lt $max_retries ]]; then
                warn "Pull failed for $svc (attempt $attempt/$max_retries), retrying..."
                sleep 5
            fi
            ((attempt++))
        done
        if [[ $attempt -gt $max_retries ]]; then
            failed+=("$svc")
        fi
    done

    # Also pull gvmd separately (no gvm- prefix)
    local attempt=1
    while [[ $attempt -le $max_retries ]]; do
        if docker compose pull gvmd 2>/dev/null; then
            break
        fi
        if [[ $attempt -lt $max_retries ]]; then
            warn "Pull failed for gvmd (attempt $attempt/$max_retries), retrying..."
            sleep 3
        fi
        ((attempt++))
    done
    if [[ $attempt -gt $max_retries ]]; then
        failed+=(gvmd)
    fi

    if [[ ${#failed[@]} -gt 0 ]]; then
        error "Failed to pull after $max_retries attempts: ${failed[*]}"
        echo ""
        echo -e "  ${YELLOW}This is often caused by a Docker+Go 1.24 bug (moby/moby#49513).${NC}"
        echo -e "  ${YELLOW}Try: echo '{\"max-concurrent-downloads\":1}' | sudo tee /etc/docker/daemon.json${NC}"
        echo -e "  ${YELLOW}Then: sudo systemctl restart docker && ./redamon.sh up${NC}"
        exit 1
    fi
    success "All GVM images pulled successfully."
}

# Run `docker compose up -d` and, when it fails, say WHY if the cause is a feed
# loader that was OOM-killed.
#
# A loader dies with a bare `Killed` and exit 137, compose reports only "didn't
# complete successfully", and `restart: on-failure:5` turns that into minutes of
# silent retries before the same opaque message (issue #176). gvmd and gvm-ospd
# are gated on these completing, so the whole GVM stack then never starts and
# nothing in the output points at the memory cap that caused it.
gvm_up_or_diagnose() {
    docker compose up -d "$@" && return 0
    local rc=$? svc cid killed exitcode oom=()
    for svc in $(docker compose config --services 2>/dev/null | grep '^gvm-'); do
        cid="$(docker compose ps -aq "$svc" 2>/dev/null | head -1)"
        [[ -n "$cid" ]] || continue
        read -r killed exitcode <<< "$(docker inspect \
            -f '{{.State.OOMKilled}} {{.State.ExitCode}}' "$cid" 2>/dev/null)"
        # A zero exit is a success whatever the OOMKilled flag says about an
        # earlier restart. OOMKilled is otherwise authoritative, but some daemon
        # versions clear it, so a bare 137 on a one-shot `cp` counts too.
        [[ "${exitcode:-0}" != "0" ]] || continue
        [[ "$killed" == "true" || "$exitcode" == "137" ]] && oom+=("$svc")
    done
    [[ ${#oom[@]} -eq 0 ]] && return "$rc"

    error "GVM feed loader(s) out of memory: ${oom[*]}"
    error "  These copy a multi-GB Greenbone feed and were killed by their memory cap."
    error "  Current cap: GVM_DATA_MEM=${GVM_DATA_MEM:-<unset>} (needs >= 512m)."
    error "  Raise it by adding this to .env ABOVE the '${_MEM_BLOCK_BEGIN}' line,"
    error "  which pins it so the governor stops recomputing it:"
    error "      GVM_DATA_MEM=1g"
    error "  Then re-run: ./redamon.sh up"
    return "$rc"
}

# ---------------------------------------------------------------------------
# Knowledge Base helpers
# ---------------------------------------------------------------------------

KB_CONFIG_YAML="$SCRIPT_DIR/services/knowledge_base/kb_config.yaml"

# Read a value from kb_config.yaml. Dotted paths are supported for nested
# keys. Falls back to $2 if the file, key, or python is unavailable.
#   $1: dotted key path (e.g. "runtime.mode" or "KB_ENABLED")
#   $2: fallback value
_kb_yaml_get() {
    local key="$1"
    local fallback="$2"
    python3 -c "
import sys, yaml
try:
    with open('$KB_CONFIG_YAML') as f:
        cfg = yaml.safe_load(f) or {}
    value = cfg
    for k in '$key'.split('.'):
        value = value[k]
    if isinstance(value, bool):
        print('true' if value else 'false')
    else:
        print(value)
except Exception:
    print('$fallback')
" 2>/dev/null || echo "$fallback"
}

# Feature gate mirroring is_gvm_enabled(). Single source of truth: the
# `.kbase-enabled` flag file, written by `install --kbase`. The README contract
# is that KB is opt-in — default install has no KB.
is_kb_enabled() {
    is_kbase_enabled
}

# --- GPU / PyTorch build variant --------------------------------------------
# The CPU-vs-CUDA PyTorch decision is made ONCE at build time and frozen. A GPU
# is "usable" only if the NVIDIA *container runtime* is present -- a bare card
# with no nvidia-container-toolkit cannot be handed to a container, so a CUDA
# image there would be pure bloat. We therefore key off the runtime, not the card.
gpu_runtime_available() {
    # Authoritative signal: an "nvidia" entry among the docker RUNTIME KEYS
    # (registered by nvidia-container-toolkit). Match keys only -- NOT docker
    # info's giant features blob, which mentions unrelated tokens.
    if docker info --format '{{range $k, $v := .Runtimes}}{{$k}} {{end}}' 2>/dev/null \
        | grep -qiw nvidia; then
        return 0
    fi
    # Fallback: a WORKING driver. The nvidia-smi *binary* can exist on a host
    # with no functional driver (it then errors), so require it to actually run.
    command -v nvidia-smi >/dev/null 2>&1 && nvidia-smi -L >/dev/null 2>&1
}

is_gpu_enabled() {
    # Explicit flag wins; otherwise auto-detect once (unless disabled explicitly).
    if [[ -f "$GPU_ENABLED_FLAG_FILE" ]]; then
        return 0
    elif [[ -f "$GPU_DISABLED_FLAG_FILE" ]]; then
        return 1
    else
        gpu_runtime_available
    fi
}

# Export TORCH_INDEX_URL for `docker compose build` and freeze the decision into
# the `.torch-variant` marker. The runtime GPU device grant (docker-compose.gpu.yml)
# is overlaid via COMPOSE_FILE ONLY when the build produced a CUDA image, so a
# CPU host never requests a device it cannot provide.
#   cu124 is a safe default CUDA series; override with TORCH_CUDA_INDEX_URL if a
#   host's driver needs a different one.
_gpu_export_env() {
    local cuda_index="${TORCH_CUDA_INDEX_URL:-https://download.pytorch.org/whl/cu124}"
    local variant="cpu"
    if is_gpu_enabled; then
        export TORCH_INDEX_URL="$cuda_index"
        variant="gpu"
    else
        export TORCH_INDEX_URL="https://download.pytorch.org/whl/cpu"
    fi
    # The marker is what every later command obeys, so a failed write is NOT
    # cosmetic: a GPU build whose marker never landed would start with no device
    # grant and silently run its CUDA image on the CPU. Say so loudly.
    if ! printf '%s' "$variant" > "$TORCH_VARIANT_MARKER" 2>/dev/null; then
        warn "Could not write $TORCH_VARIANT_MARKER (root-owned or read-only checkout?)."
        warn "  Built variant '$variant' will not be remembered; GPU device access may not be applied."
        warn "  If an earlier run used sudo:  sudo chown -R \"\$(id -un):\$(id -gn)\" \"$SCRIPT_DIR\""
    fi
}

# Compose-file args for the GPU device grant. Empty on CPU builds.
# Call sites that pass their OWN -f flags (e.g. $DEV_COMPOSE) MUST append this,
# because explicit -f overrides $COMPOSE_FILE entirely.
GPU_COMPOSE_ARGS=""

# Apply the GPU runtime device grant, but ONLY when the frozen build marker says
# a CUDA image was built. Two mechanisms, deliberately:
#   * COMPOSE_FILE  -> every plain `docker compose ...` call site, no edits.
#   * GPU_COMPOSE_ARGS -> the call sites that pass explicit -f (dev overlay),
#     where COMPOSE_FILE is ignored by compose.
# Inert on CPU builds -> zero risk on GPU-less hosts.
_gpu_compose_overlay() {
    local variant
    variant="$(cat "$TORCH_VARIANT_MARKER" 2>/dev/null)" || variant=""

    # Re-export the FROZEN build arg (read from the marker, never re-detected).
    # `up` does not build today, but any build reached from a runtime command must
    # reproduce the variant this install was built with rather than silently
    # falling back to the compose default (CPU).
    case "$variant" in
        gpu) export TORCH_INDEX_URL="${TORCH_CUDA_INDEX_URL:-https://download.pytorch.org/whl/cu124}" ;;
        cpu) export TORCH_INDEX_URL="https://download.pytorch.org/whl/cpu" ;;
    esac

    [[ "$variant" == "gpu" ]] || return 0

    # The build decision is frozen, but the HARDWARE can disappear underneath it
    # (driver upgrade, toolkit removed, image rsynced to another host). Requesting
    # an nvidia device the daemon cannot provide makes `up` fail hard and the whole
    # stack unstartable. Degrade to CPU with a loud warning instead: a CUDA image
    # runs fine on CPU, just slower.
    if ! gpu_runtime_available; then
        warn "Built for GPU (.torch-variant=gpu) but no NVIDIA container runtime is available now."
        warn "  Starting WITHOUT GPU access (the CUDA image falls back to CPU)."
        warn "  Restore nvidia-container-toolkit, or rebuild for CPU: ./redamon.sh install --cpu"
        return 0
    fi

    # Idempotent: install -> _kb_bootstrap both call this in one process.
    if [[ "${COMPOSE_FILE:-}" != *"docker-compose.gpu.yml"* ]]; then
        # Absolute paths: some call sites run from a different cwd.
        local base_file="$SCRIPT_DIR/docker-compose.yml"
        local overlay_file="$SCRIPT_DIR/docker-compose.gpu.yml"
        local separator="${COMPOSE_PATH_SEPARATOR:-:}"
        case "$OSTYPE" in
            msys*|cygwin*)
                # Windows Compose needs native paths and its native list separator.
                base_file=$(cygpath -m "$base_file")
                overlay_file=$(cygpath -m "$overlay_file")
                separator="${COMPOSE_PATH_SEPARATOR:-;}"
                ;;
        esac
        export COMPOSE_FILE="${COMPOSE_FILE:-$base_file}${separator}${overlay_file}"
    fi
    GPU_COMPOSE_ARGS="-f $SCRIPT_DIR/docker-compose.gpu.yml"
}

# Export KB-related env vars so downstream processes (docker compose, make)
# see a value that matches the flag file. Called from every cmd_* that
# shells out to docker compose. Always exports — the flag is authoritative,
# any pre-existing $KB_ENABLED in the environment is overwritten so direct
# `KB_ENABLED=true docker compose up` shenanigans can't lie to the agent
# when the image was built without KB deps.
_kb_export_env() {
    if is_kbase_enabled; then
        export KB_ENABLED="true"
        export SKIP_KB="false"
    else
        export KB_ENABLED="false"
        export SKIP_KB="true"
    fi
}

# Wait for the Neo4j container to become healthy. Starts it if not running.
# Returns 0 on success, 1 on timeout.
# Every Knowledge Base `make` goes through here so it inherits the REAL Neo4j
# credentials from .env (redamon.sh does not source .env), instead of the Makefile's
# insecure `changeme123` fallback which fails auth on any rotated/custom-password DB
# (#160 / the `kb stats` failure). An env var (even empty) defeats the Makefile's
# `?=` default, so this is authoritative.
_kb_make() {
    NEO4J_PASSWORD="$(_env_get NEO4J_PASSWORD)" \
        make -C services/knowledge_base "$@"
}

_kb_wait_neo4j() {
    if ! docker ps --format '{{.Names}}' | grep -q '^redamon-neo4j$'; then
        info "Neo4j not running — starting it..."
        docker compose up -d neo4j
    fi

    info "Waiting for Neo4j to become healthy..."
    local waited=0
    local max_wait=60
    while [[ $waited -lt $max_wait ]]; do
        local health
        health=$(docker inspect --format='{{.State.Health.Status}}' \
                   redamon-neo4j 2>/dev/null || echo "unknown")
        if [[ "$health" == "healthy" ]]; then
            success "Neo4j is healthy"
            return 0
        fi
        sleep 2
        waited=$((waited + 2))
    done

    error "Neo4j did not become healthy within ${max_wait}s"
    error "Check: docker logs redamon-neo4j"
    return 1
}

# Check if the agent container has a CUDA-capable GPU available.
_kb_has_gpu() {
    docker exec redamon-agent python -c \
        "import torch; exit(0 if torch.cuda.is_available() else 1)" &>/dev/null
}

# Check if .env has an embedding API configured and ready to use.
_kb_has_api_key() {
    local env_file="$SCRIPT_DIR/.env"
    [[ -f "$env_file" ]] || return 1
    local use_api key
    use_api=$(grep -E '^KB_EMBEDDING_USE_API=' "$env_file" 2>/dev/null \
              | cut -d= -f2 | tr -d '"' | tr -d "'")
    key=$(grep -E '^KB_EMBEDDING_API_KEY=' "$env_file" 2>/dev/null \
          | cut -d= -f2 | tr -d '"' | tr -d "'")
    [[ "$use_api" == "true" && -n "$key" ]]
}

# Detect the best ingestion profile and show terminal feedback.
# Prints the chosen profile name to stdout. Shows an interactive
# prompt on CPU-only systems asking the user whether to run full
# ingestion or quick-start with fewer sources.
_kb_choose_profile() {
    if _kb_has_api_key; then
        local base_url
        base_url=$(grep -E '^KB_EMBEDDING_API_BASE_URL=' "$SCRIPT_DIR/.env" \
                   | cut -d= -f2 | tr -d '"' | tr -d "'")
        info "KB Embedding: API mode (${base_url:-https://api.openai.com/v1})" >&2
        info "Ingesting all lite sources via API embeddings..." >&2
        echo "lite"
        return
    fi

    if _kb_has_gpu; then
        info "KB Embedding: GPU detected" >&2
        info "Ingesting all lite sources with GPU acceleration..." >&2
        echo "lite"
        return
    fi

    # CPU-only with existing FAISS data: skip the interactive prompt.
    # The manifest dedup will skip unchanged chunks anyway, so a re-run
    # finishes in seconds. To upgrade the profile, use:
    #   ./redamon.sh kb build lite
    #
    # Note: FAISS files are created by Docker (root-owned, mode 600), so
    # we cannot read their contents as a normal user. Use -s (non-zero size)
    # instead of trying to parse the JSON.
    local faiss_index="$SCRIPT_DIR/services/knowledge_base/data/index.faiss"
    if [[ -s "$faiss_index" ]]; then
        info "KB Embedding: CPU mode (FAISS index exists, refreshing unchanged chunks)" >&2
        echo "cpu-lite"
        return
    fi

    # First-time CPU-only: show explanation and let user choose
    echo ""                                                            >&2
    echo "==========================================================" >&2
    echo "  Knowledge Base -- Embedding Configuration"                 >&2
    echo "==========================================================" >&2
    echo ""                                                            >&2
    echo "  No GPU and no embedding API key detected."                 >&2
    echo "  The KB needs to convert security datasets into vector"     >&2
    echo "  embeddings. On CPU this is slow for large datasets."       >&2
    echo ""                                                            >&2
    echo "  Source          Chunks    Est. time on CPU"                 >&2
    echo "  --------------- --------- ----------------"                >&2
    echo "  tool_docs            ~35   ~2 min"                         >&2
    echo "  gtfobins            ~400   ~7 min"                         >&2
    echo "  lolbas              ~450   ~7 min"                         >&2
    echo "  owasp               ~880   ~35 min"                        >&2
    echo "  exploitdb        ~45,000   ~3 hours"                       >&2
    echo ""                                                            >&2
    echo "  Option 1: Quick start (~15 min)"                           >&2
    echo "    Ingest tool_docs + gtfobins + lolbas only."              >&2
    echo "    You can add owasp/exploitdb later."                      >&2
    echo ""                                                            >&2
    echo "  Option 2: Full ingestion (~4 hours)"                       >&2
    echo "    Ingest all 5 sources now. Go grab a coffee."             >&2
    echo ""                                                            >&2
    echo "  Tip: To skip this wait in the future, configure an"        >&2
    echo "  embedding API in .env (see .env.example):"                 >&2
    echo "    KB_EMBEDDING_USE_API=true"                                >&2
    echo "    KB_EMBEDDING_API_KEY=sk-..."                              >&2
    echo "    KB_EMBEDDING_API_BASE_URL=  (leave empty for OpenAI)"    >&2
    echo "  With an API, full ingestion takes ~2-3 minutes."           >&2
    echo ""                                                            >&2
    echo "==========================================================" >&2
    echo ""                                                            >&2

    read -rp "  Run full ingestion now? [y/N] " full_ingest </dev/tty

    if [[ "$full_ingest" =~ ^[Yy]$ ]]; then
        info "Full ingestion selected. This will take a while..." >&2
        echo "lite"
    else
        info "Quick start selected (tool_docs + gtfobins + lolbas)" >&2
        echo "cpu-lite"
    fi
}

# Internal: run `make kb-build-<profile>` with Neo4j health check first.
# Fails gracefully -- callers decide whether to treat failure as fatal.
_kb_bootstrap() {
    local profile="${1:-lite}"
    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)
    _kb_wait_neo4j || return 1
    info "Bootstrapping Knowledge Base (profile=${profile})..."
    _kb_make "kb-build-${profile}" MODE=docker
}

# Status helpers: read KB and Tavily state directly from disk/env without
# requiring Python deps, running containers, or Neo4j connections. These
# should always succeed (or return a safe fallback) so `./redamon.sh status`
# works in any state.

# Count FAISS vectors by reading chunk_ids.json directly. No Python dep
# required — uses python3's stdlib json module, which is always present.
# Returns "0" if the file is missing or unreadable.
_kb_get_faiss_count() {
    local chunk_ids="$SCRIPT_DIR/services/knowledge_base/data/chunk_ids.json"
    if [[ ! -f "$chunk_ids" ]]; then
        echo "0"
        return
    fi
    python3 -c "
import json, sys
try:
    with open('$chunk_ids') as f:
        data = json.load(f)
    print(len(data) if isinstance(data, list) else 0)
except Exception:
    print('0')
" 2>/dev/null || echo "0"
}

# Count Neo4j KBChunk nodes via cypher-shell inside the neo4j container.
# Returns "0" if the container isn't running, "unknown" if the query fails.
_kb_get_neo4j_count() {
    if ! docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^redamon-neo4j$'; then
        echo "0"
        return
    fi
    # S13: after rotation the live password is in .env, NOT changeme123 and NOT in
    # this shell's env (redamon.sh does not source .env). Read .env first so the
    # `status` / `kb stats` KB count still authenticates on a rotated DB; fall back
    # to the env var, then the fresh-install default.
    local pass
    pass="$(_env_get NEO4J_PASSWORD)"
    pass="${pass:-${NEO4J_PASSWORD}}"
    local user="${NEO4J_USER:-neo4j}"
    local count
    count=$(docker exec redamon-neo4j cypher-shell \
        -u "$user" -p "$pass" --format plain \
        "MATCH (c:KBChunk) RETURN count(c) AS total" 2>/dev/null \
        | tail -n 1 | tr -d '[:space:]"' || true)
    # Validate it's a non-negative integer; fall back to unknown otherwise
    if [[ "$count" =~ ^[0-9]+$ ]]; then
        echo "$count"
    else
        echo "unknown"
    fi
}

# ---------------------------------------------------------------------------
# Commands
# ---------------------------------------------------------------------------

cmd_install() {
    local gvm_mode="false"
    local kbase_mode="false"
    local gpu_mode=""   # "on" | "off" | "" (auto-detect); set by --gpu / --cpu

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --gvm)   gvm_mode="true" ;;
            --kbase) kbase_mode="true" ;;
            --gpu)   gpu_mode="on" ;;
            --cpu)   gpu_mode="off" ;;
            *) error "Unknown flag: $1"; exit 1 ;;
        esac
        shift
    done

    print_banner
    check_prerequisites
    # A fresh install cannot pull, so this cannot block anything here - but a
    # `sudo ./redamon.sh install` is exactly what creates the root-owned files
    # that break the NEXT update. Say so at the point the mistake is made.
    _warn_root_owned_runtime_files

    # Gate BEFORE any Docker work. `install` used to build 16 images (30-60 min)
    # and only then discover the host was too small, because the RAM gate lived
    # in cmd_up and install ends in a raw `docker compose up -d`. `update` never
    # ran it at all.
    if ! preflight_ram_gate; then exit 1; fi
    if ! preflight_disk_gate "$DISK_FULL_BUILD_GB" "install"; then exit 1; fi

    local version
    version="$(get_version)"
    info "Installing RedAmon v${version}..."
    if [[ "$gvm_mode" == "true" ]]; then
        info "Mode: Full stack (with GVM/OpenVAS)"
        touch "$GVM_FLAG_FILE"
    else
        info "Mode: Core services (without GVM/OpenVAS)"
        rm -f "$GVM_FLAG_FILE"
    fi
    # KB is OPT-IN at install time. The install always writes ONE of the two
    # markers (.kbase-enabled or .kbase-disabled) so the user's explicit choice
    # is sticky — `clean` keeps KB data on disk, and without an explicit
    # "disabled" marker the migration heuristic would later see leftover FAISS
    # data and re-enable KB. The legacy `.skipkbase` flag is removed.
    rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
    if [[ "$kbase_mode" == "true" ]]; then
        info "Mode: Including Knowledge Base (--kbase)"
        touch "$KBASE_FLAG_FILE"
        rm -f "$KBASE_DISABLED_FLAG_FILE"
    else
        info "Mode: Skipping Knowledge Base (default; pass --kbase to enable)"
        rm -f "$KBASE_FLAG_FILE"
        touch "$KBASE_DISABLED_FLAG_FILE"
    fi
    # GPU is opt-in like KB. --gpu / --cpu are sticky (mirrors the KB markers);
    # with neither, auto-detect the NVIDIA container runtime at build time.
    if [[ "$gpu_mode" == "on" ]]; then
        info "Mode: GPU PyTorch build (--gpu, CUDA wheel for the agent KB)"
        touch "$GPU_ENABLED_FLAG_FILE"; rm -f "$GPU_DISABLED_FLAG_FILE"
    elif [[ "$gpu_mode" == "off" ]]; then
        info "Mode: CPU-only PyTorch build (--cpu)"
        touch "$GPU_DISABLED_FLAG_FILE"; rm -f "$GPU_ENABLED_FLAG_FILE"
    else
        rm -f "$GPU_ENABLED_FLAG_FILE" "$GPU_DISABLED_FLAG_FILE"
        if gpu_runtime_available; then
            info "Mode: GPU PyTorch build (auto-detected NVIDIA container runtime)"
        else
            info "Mode: CPU-only PyTorch build (no NVIDIA container runtime detected)"
        fi
    fi
    _kb_export_env
    _gpu_export_env      # freeze CPU/CUDA torch decision into .torch-variant
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)
    echo ""

    # Export version for docker build arg
    export_version

    # Generate auth secrets if not present
    ensure_auth_secrets
    ensure_volume_ownership
    ensure_db_secrets
    # Pin a strong GVM admin password BEFORE `up`, so the orchestrator starts with
    # it; reconcile_gvm_admin_password (post-up) applies it to the live gvmd.
    ensure_gvm_secret

    # Build all images (tools + core services + the on-demand capture proxy).
    # The capture-proxy / traffic-ingest pair lives in the "capture" profile and is
    # spawned on demand by the orchestrator (never by `up`), but its image
    # (redamon-capture-proxy:latest) must still EXIST or the first Settings toggle
    # fails with an image-not-found pull error. Building it here — alongside tools —
    # guarantees a fresh install can start capture without any extra step.
    info "Building all images (this may take a while on first run)..."
    compose_build --profile tools --profile capture build

    # Reap the images the build just orphaned. A rebuild does not replace an image
    # in place: it builds a new one and MOVES the tag, leaving the previous image
    # untagged and uncollected. On a genuinely fresh install this is a no-op (there
    # is nothing to orphan), but `install` re-run on a host that already has RedAmon
    # images rebuilds the ENTIRE set in one shot -- a retry after a failed install, a
    # `--gvm`/`--kbase` mode switch, or an `install` used where `update` was meant.
    # That is the largest orphaning event the script can produce, and it was the only
    # build path with no cleanup; cmd_update has always done this after its rebuilds.
    #
    # `prune -f`, NEVER `prune -af`: the plain form removes only untagged images that
    # no container references. `-af` removes every image not backing a RUNNING
    # container, and at this point in install NOTHING is running yet -- it would
    # delete the whole tool set that was just built (tool images are build-only and
    # never run) and the core images too, immediately after paying for them.
    docker image prune -f >/dev/null 2>&1 || true

    # AFTER the tool build: the sync runs inside the analyzer image, so calling
    # it earlier silently skipped on a fresh install and left the offline OSV
    # database empty - the supply-chain feature would then report "no <eco>
    # ecosystem" on every scan until someone ran supply-chain-sync by hand.
    ensure_osv_db
    ensure_sca_intel

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    # Start services (force-recreate ensures compose changes like command: are applied)
    info "Starting services..."
    if [[ "$gvm_mode" == "true" ]]; then
        gvm_up_or_diagnose --force-recreate
    else
        # shellcheck disable=SC2086
        docker compose up -d --force-recreate $CORE_SERVICES
    fi

    # Verify BEFORE announcing. See verify_core_running(). This matters most on a
    # fresh install: it is the run where a wrong .env, an unwritable volume, or a
    # container OOM is most likely, and the one where a false "ready!" sends the
    # operator off to configure a reverse proxy in front of nothing.
    if ! verify_core_running; then
        exit 1
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon v${version} is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: start the orchestrator-spawned proxy if the master
    # switch is on (it is not compose-managed, so `up`/restart won't bring it back).
    ensure_capture_proxy_running

    # Bootstrap the Knowledge Base if enabled (reads KB_ENABLED from kb_config.yaml).
    # Install always runs a fresh bootstrap -- first-time setup populates FAISS +
    # Neo4j from committed caches. Graceful failure: if bootstrap fails
    # (network, missing deps, etc.) the agent still starts with an empty KB
    # and the user gets a clear retry command.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB bootstrap failed -- agent will start with an empty KB"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    else
        info "KB_ENABLED=false -- skipping Knowledge Base bootstrap"
    fi

    echo ""
    echo -e "  ${CYAN}Status:${NC}  ./redamon.sh status"
    echo ""
    echo -e "  ${YELLOW}If RedAmon is useful to you, a GitHub star helps others find the project:${NC}"
    echo -e "  ${CYAN}https://github.com/samugit83/redamon${NC}"
    echo ""
    if [[ "$gvm_mode" == "true" ]]; then
        # Apply the pinned GVM_PASSWORD to the live gvmd 'admin' user (gvmd only
        # created it during the `up` above). Runs last so core readiness is
        # announced first; best-effort (never aborts the install).
        reconcile_gvm_admin_password
        warn "GVM/OpenVAS feed sync takes ~30 minutes on first run."
        echo -e "  ${CYAN}GVM credentials:${NC} admin / (see GVM_PASSWORD in .env)"
    fi
}

cmd_update() {
    # --gpu / --cpu are accepted here too, so switching the PyTorch variant does
    # not require a full `install`. Unlike install, omitting them PRESERVES the
    # existing sticky choice (same contract as the GVM/KB flags: an update must
    # never silently flip a decision the user made at install time).
    local gpu_mode="" update_args=()
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --gpu) gpu_mode="on";  update_args+=("$1") ;;
            --cpu) gpu_mode="off"; update_args+=("$1") ;;
            *) error "Unknown flag: $1"; exit 1 ;;
        esac
        shift
    done
    if [[ "$gpu_mode" == "on" ]]; then
        info "Switching to a GPU PyTorch build (--gpu)"
        touch "$GPU_ENABLED_FLAG_FILE"; rm -f "$GPU_DISABLED_FLAG_FILE"
    elif [[ "$gpu_mode" == "off" ]]; then
        info "Switching to a CPU-only PyTorch build (--cpu)"
        touch "$GPU_DISABLED_FLAG_FILE"; rm -f "$GPU_ENABLED_FLAG_FILE"
    fi

    # Before anything writes: a mixed root/user checkout fails halfway through
    # otherwise, and the resulting errors point nowhere near the real cause.
    _assert_checkout_writable
    _warn_root_owned_runtime_files

    _migrate_reorg_layout
    _migrate_legacy_kbase_flag
    _kb_export_env
    _gpu_export_env      # freeze CPU/CUDA torch decision into .torch-variant
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)

    print_banner
    check_prerequisites

    local old_version
    old_version="$(get_version)"
    info "Current version: v${old_version}"
    info "Checking for updates..."
    echo ""

    # Save current HEAD
    local old_head new_head
    if [[ -n "${REDAMON_UPDATE_FROM:-}" ]]; then
        # We were re-exec'd by our previous self after the pull (see below). Reuse
        # the recorded pre-pull HEAD and do NOT pull again — just run the rebuild
        # logic from the freshly-pulled (newer) script.
        old_head="$REDAMON_UPDATE_FROM"
        new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"
    else
        old_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

        # Drop RedAmon's own runtime scribbles first — they are the single most
        # common reason this pull fails, and they are not the user's changes.
        _restore_runtime_tracked_files

        # Pull latest (upstream tracking branch, then origin/master), diagnosing
        # and self-healing the failure modes users actually hit.
        _update_pull

        # A heal moved HEAD by reset, not by fast-forward. Diff from the real
        # pre-divergence base so the rebuild map, the up-to-date check and the
        # REDAMON_UPDATE_FROM handed to the re-exec all see only what the RELEASE
        # changed.
        if [[ -n "$UPDATE_BASE_HEAD" ]]; then
            old_head="$UPDATE_BASE_HEAD"
        fi

        new_head="$(git -C "$SCRIPT_DIR" rev-parse HEAD)"

        if [[ "$old_head" == "$new_head" ]]; then
            success "Already up to date (v$(get_version))."
            return
        fi

        # Self-heal across versions: re-exec the freshly-pulled script so the
        # update logic from the version being INSTALLED runs (it may know about
        # services or build rules this older copy does not — e.g. a new service
        # added in the target release). Guarded by REDAMON_UPDATE_FROM so we do
        # not pull or loop again.
        export REDAMON_UPDATE_FROM="$old_head"
        exec bash "$SCRIPT_DIR/redamon.sh" update ${update_args[@]+"${update_args[@]}"}
    fi

    local new_version
    new_version="$(get_version)"
    info "Updating v${old_version} -> v${new_version}"
    echo ""

    # Detect what changed
    local changed_files
    changed_files="$(git -C "$SCRIPT_DIR" diff --name-only "$old_head" "$new_head")"

    # Map changed paths to services
    local rebuild_core=()
    local rebuild_tools=()
    local rebuild_all=false

    if echo "$changed_files" | grep -q "^docker-compose\.yml$"; then
        rebuild_all=true
    fi

    # Track services that need restart only (volume-mounted source code changes)
    local restart_only=()

    if [[ "$rebuild_all" == "true" ]]; then
        info "docker-compose.yml changed -- rebuilding core service images"
        rebuild_core=(recon-orchestrator kali-sandbox agent webapp docker-broker)
    else
        # webapp: always needs rebuild (no volume mount in production)
        if echo "$changed_files" | grep -q "^webapp/"; then
            rebuild_core+=(webapp)
        fi

        # recon-orchestrator: rebuild only if Dockerfile/requirements changed, else restart
        if echo "$changed_files" | grep -q "^recon_orchestrator/\(Dockerfile\|requirements\)"; then
            rebuild_core+=(recon-orchestrator)
        elif echo "$changed_files" | grep -q "^recon_orchestrator/"; then
            restart_only+=(recon-orchestrator)
        fi

        # kali-sandbox: rebuild only if Dockerfile/entrypoint changed, else restart
        if echo "$changed_files" | grep -q "^mcp/kali-sandbox/\(Dockerfile\|entrypoint\)"; then
            rebuild_core+=(kali-sandbox)
        elif echo "$changed_files" | grep -q "^mcp/"; then
            restart_only+=(kali-sandbox)
        fi

        # agent: always rebuild when agentic/ changes — source code is baked into
        # the image (no volume mount for ./agentic:/app), so restart alone won't
        # pick up .py changes.
        if echo "$changed_files" | grep -q "^agentic/"; then
            rebuild_core+=(agent)
        elif echo "$changed_files" | grep -qE "^(services/knowledge_base|graph_db)/"; then
            rebuild_core+=(agent)
        fi

        # docker-broker: the Docker-socket filtering proxy. Rebuild when its
        # source changes (it builds from ./services/docker_broker, no volume mount).
        if echo "$changed_files" | grep -q "^services/docker_broker/"; then
            rebuild_core+=(docker-broker)
        fi
    fi

    # Tool-profile images build ONLY from their own source dirs — a docker-compose.yml
    # change never alters their content. So rebuild a tool image ONLY when its source
    # actually changed, even under rebuild_all. This avoids spuriously rebuilding heavy
    # / fragile tool images (e.g. ai-attack-surface, whose pyrit deps need a Rust
    # toolchain on arm64) on an unrelated compose change.
    if echo "$changed_files" | grep -q "^recon/"; then
        rebuild_tools+=(recon)
    fi
    # wcvs: the Web Cache Vulnerability Scanner image (web cache poisoning module),
    # run docker-in-docker by the recon container. Build-only; rebuild when its
    # Dockerfile (or pinned WCVS_REF) changes.
    if echo "$changed_files" | grep -q "^scanners/wcvs/"; then
        rebuild_tools+=(wcvs)
    fi
    if echo "$changed_files" | grep -q "^scanners/gvm_scan/"; then
        rebuild_tools+=(vuln-scanner)
    fi
    if echo "$changed_files" | grep -q "^scanners/github_secret_hunt/"; then
        rebuild_tools+=(github-secret-hunter)
    fi
    if echo "$changed_files" | grep -q "^scanners/trufflehog_scan/"; then
        rebuild_tools+=(trufflehog-scanner)
    fi
    if echo "$changed_files" | grep -q "^scanners/baddns_scan/"; then
        rebuild_tools+=(baddns-scanner)
    fi
    # ai-attack-surface: heavy build-only image (Node + promptfoo + per-tool venvs).
    # The adapter .py files are volume-mounted into the scan container at spawn
    # (hot-reload, no rebuild); ONLY the baked-in toolchain — the Dockerfile or any
    # requirements file — needs a rebuild.
    if echo "$changed_files" | grep -qE "^scanners/ai_attack_surface_scan/(Dockerfile|.*requirements)"; then
        rebuild_tools+=(ai-attack-surface)
    fi
    # codefix-sandbox: the isolated CodeFix build sandbox (T6/E10). Build-only
    # image; rebuild when anything in its build context changes.
    if echo "$changed_files" | grep -q "^scanners/codefix_sandbox/"; then
        rebuild_tools+=(codefix-sandbox)
    fi
    # supply-chain (L1 CLEAN scanner): the .py source is volume-mounted into the
    # spawned scan container (hot-reload), so rebuild the image ONLY when the
    # baked layer changes -- the Dockerfile (osv-scanner binary) or requirements.
    # Matches recon-orchestrator's precise rule. On the FIRST update onto this
    # release these files are new, so the image is built; thereafter a pure .py
    # change hot-reloads at spawn with no rebuild.
    if echo "$changed_files" | grep -qE "^scanners/supply_chain_scan/(Dockerfile|requirements)"; then
        rebuild_tools+=(supply-chain)
    fi
    # supply-chain-analyzer (DIRTY analyzer): entrypoint.py is BAKED (COPY), not
    # mounted, so rebuild on ANY change to the analyzer dir (entrypoint or Dockerfile).
    if echo "$changed_files" | grep -q "^scanners/supply_chain_analyzer/"; then
        rebuild_tools+=(supply-chain-analyzer)
    fi
    # capture-proxy / traffic-ingest (HTTP Traffic Capture): both share the
    # redamon-capture-proxy:latest image, built from scanners/capture_proxy/. It is in the
    # "capture" profile — never started by `up`, but SPAWNED on demand by the
    # orchestrator, which just runs the image (no on-demand build; scanners/capture_proxy/ is
    # not mounted into the orchestrator). So `update` MUST rebuild it here or the
    # proxy would keep serving stale capture/ingest/redaction/egress code. Handled
    # separately from rebuild_tools because it needs its own profile flag to build.
    local rebuild_capture=false
    if echo "$changed_files" | grep -q "^scanners/capture_proxy/"; then
        rebuild_capture=true
    fi
    # The proxy image also COPYs two files OUT of recon_orchestrator/ at build
    # time (hard_guardrail.py, ip_denylist.py — the shared hostname and
    # resolved-IP denylists). Those live outside scanners/capture_proxy/, so a
    # change to either would otherwise leave the proxy enforcing a stale guard
    # while the orchestrator enforced the new one. Keep this list in step with
    # the COPY lines in scanners/capture_proxy/Dockerfile.
    if echo "$changed_files" | grep -qE "^recon_orchestrator/(hard_guardrail|ip_denylist)\.py$"; then
        rebuild_capture=true
    fi

    # Remember whether the stack was serving BEFORE anything is touched. `update`
    # only restarts what it rebuilds, so a user who ran `down` first, or who
    # updates before ever starting, must not be told the update failed at the end.
    local stack_was_up=false
    if _service_running webapp; then
        stack_was_up=true
    fi

    # Disk gate BEFORE the first build. compose_build gates itself too, but the
    # tool-image build below runs in an `if !` condition so it only warns and
    # continues — on a full disk that would march on and fail again at the core
    # rebuild. Checking once here aborts the update while everything still works,
    # which is the whole point: a failed update must never leave the host worse
    # off than before it started.
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 || "$rebuild_capture" == "true" ]]; then
        if ! preflight_disk_gate "$DISK_FULL_BUILD_GB" "update to v${new_version}"; then
            error "Update aborted before any image was touched. v${old_version} is still installed and running."
            exit 1
        fi
    fi
    # RAM gate too: `update` never ran one, so a release that adds a service (or
    # a host that shrank) was only discovered after the rebuild. Same contract as
    # the disk gate above -- abort while the old version is still working.
    if ! preflight_ram_gate; then
        error "Update aborted before any image was touched. v${old_version} is still installed and running."
        exit 1
    fi

    # Export version for build arg
    export_version

    # Generate auth/db secrets BEFORE recreating any container. A release may add
    # new inbound secrets (e.g. AGENT_WS_TICKET_SECRET for S6, TUNNEL_AUTH_TOKEN
    # for I19/S14); if the recreate below runs before they exist in .env, the
    # containers start with empty values and those protections FAIL OPEN until the
    # next recreate. Generating first guarantees a single `update` fully enforces.
    # Both are idempotent (append-if-absent), so this is a no-op once present.
    ensure_auth_secrets
    ensure_volume_ownership
    ensure_db_secrets
    # Same generate-before-recreate ordering as the DB/auth secrets: pin
    # GVM_PASSWORD so the recon-orchestrator recreate below picks it up.
    ensure_gvm_secret

    # Rebuild tool-profile images. A tool image is build-only (not a running core
    # service), so a failure here must NOT abort the rest of the update (core
    # services, broker, auth key). Warn and continue; the existing tool image keeps
    # working until its build is fixed.
    if [[ ${#rebuild_tools[@]} -gt 0 ]]; then
        info "Rebuilding tool images: ${rebuild_tools[*]}"
        if ! compose_build --profile tools build "${rebuild_tools[@]}"; then
            warn "One or more tool images failed to build (${rebuild_tools[*]}); continuing with the core update. Re-run the build later: docker compose --profile tools build ${rebuild_tools[*]}"
        fi
    fi

    # AFTER the tool rebuild: the sync runs inside the analyzer image, so a
    # release that rebuilds it (or a prior `clean` that removed it) must not be
    # synced against a missing image.
    ensure_osv_db
    ensure_sca_intel

    # Rebuild the capture-proxy image if its source changed, then refresh a running
    # proxy onto it. Build-only + best-effort: a failure must not abort the update.
    if [[ "$rebuild_capture" == "true" ]]; then
        info "Rebuilding capture proxy image (redamon-capture-proxy:latest)..."
        if ! compose_build --profile capture build capture-proxy; then
            warn "capture-proxy image failed to build; the existing image keeps working. Re-run later: docker compose --profile capture build capture-proxy"
        else
            _reconcile_capture_if_running
        fi
    fi

    # Rebuild core service images
    if [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Rebuilding service images: ${rebuild_core[*]}"
        compose_build build "${rebuild_core[@]}"
    fi

    # Clean up dangling images left by rebuilds
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        docker image prune -f >/dev/null 2>&1 || true
    fi

    # Restart rebuilt core services (tool images are build-only, not running).
    # When docker-compose.yml changed (rebuild_all), recreate ALL core services so
    # compose-level changes — e.g. the memory-governor mem_limits + neo4j heap —
    # reach the NON-rebuilt ones too (neo4j, postgres). A per-service --no-deps loop
    # would skip those. export_resource_caps first so the adaptive per-service caps
    # are applied, matching `up`.
    if [[ "$rebuild_all" == "true" ]]; then
        info "Recreating core services to apply docker-compose.yml changes..."
        export_resource_caps
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    elif [[ ${#rebuild_core[@]} -gt 0 ]]; then
        info "Restarting rebuilt services..."
        for svc in "${rebuild_core[@]}"; do
            docker compose up -d --no-deps "$svc"
        done
    fi

    # Converge the GVM stack onto the current compose config + .env.
    #
    # This runs on EVERY GVM-enabled update, not only when docker-compose.yml
    # changed. The per-service memory caps live in .env, which the governor
    # rewrites on every run, so a release that only touches redamon.sh (e.g. the
    # GVM_DATA_MEM floor that fixes #176) would otherwise leave the old cap baked
    # into the running containers until some unrelated later `up`. A plain
    # `up -d` recreates exactly the containers whose config drifted and leaves
    # the rest alone, so the nothing-changed case costs nothing.
    #
    # Enumerate EVERY gvm-* service from the compose file, not just the four
    # long-running ones. Naming only those relies on depends_on to pull in the
    # feed loaders, and gvm-notus-data has no depends_on edge, so it alone would
    # be skipped and keep its stale (too-small) GVM_DATA_MEM cap. Deriving the
    # list from `docker compose config` (as pull_gvm_images does) means it cannot
    # drift from the file. compose recreates exactly the containers whose config
    # changed -- so a loader whose only change is the new cap is re-run, while an
    # unchanged one is left alone.
    if is_gvm_enabled; then
        # `gvmd` has no `gvm-` prefix, so the grep misses it; append it the same
        # way pull_gvm_images does. Without it the runtime scanner daemon would
        # keep its stale config on a rebuild_all update.
        local gvm_svcs
        gvm_svcs="$(docker compose config --services 2>/dev/null | grep '^gvm-' | tr '\n' ' ')"
        [[ -n "$gvm_svcs" ]] && gvm_svcs="$gvm_svcs gvmd"
        if [[ -z "$gvm_svcs" ]]; then
            warn "No gvm-* services in the compose config; skipping GVM convergence."
        else
            local gvm_flags=()
            if [[ "$rebuild_all" == "true" ]]; then
                info "Recreating GVM containers to apply compose changes..."
                pull_gvm_images true
                gvm_flags=(--force-recreate)
            else
                info "Converging GVM containers onto the current resource caps..."
            fi
            # Non-fatal: an update must still finish, bump the version and run its
            # own stack verification even if GVM itself will not come up.
            # shellcheck disable=SC2086
            gvm_up_or_diagnose "${gvm_flags[@]}" $gvm_svcs || warn "GVM stack did not converge -- see above; core services are unaffected."
        fi
    fi

    # Converge the gvmd 'admin' password onto GVM_PASSWORD from .env. Runs on every
    # GVM-enabled update (self-guards + idempotent), so an existing install left on
    # a stale/mismatched GVM admin — e.g. one provisioned before this fix — is
    # repaired in one `update`, not just when docker-compose.yml changed.
    is_gvm_enabled && reconcile_gvm_admin_password

    # Restart services with volume-mounted code changes (no rebuild needed).
    #
    # `up -d --no-deps`, NOT `docker compose restart`: restart reuses the
    # EXISTING container, and a container's environment is fixed at creation
    # time. So a release that both changes orchestrator/mcp source AND adds a
    # new secret would restart the service onto the new code with the OLD env -
    # the new secret missing, its protection failing open until some unrelated
    # later `up` happened to recreate the container. That silently defeats the
    # "generate secrets before recreating" ordering above.
    #
    # Verified with a scratch compose project: after rewriting .env,
    # `compose restart` still reported the old value and only `compose up -d`
    # picked up the new one.
    #
    # Recreating also still picks up the volume-mounted source change, so this
    # is strictly better; it costs one container recreate.
    #
    # `--force-recreate` is REQUIRED, not optional. A volume-mounted `.py`-only
    # change alters no image and no container config, so a plain `up -d` sees no
    # drift and leaves the OLD process running — the long-lived uvicorn/python
    # process never re-reads the file, and the new code (e.g. a new orchestrator
    # endpoint) is on disk but not served until some unrelated later recreate.
    # Without force it only "worked" incidentally, when the per-service resource
    # caps the previous `up` exported happened to differ from this update shell;
    # an install that pins those caps in .env has no such drift and would silently
    # ship stale orchestrator/MCP code. Forcing the recreate makes the restart
    # deterministic. Safe: these services are stateless per-container (code is
    # mounted, persistent state lives in volumes/DB).
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        info "Recreating services for code changes: ${restart_only[*]}"
        for svc in "${restart_only[@]}"; do
            docker compose up -d --no-deps --force-recreate "$svc"
        done
    fi

    # An update that leaves the stack down must not report success. This is the
    # exact gap the v6.1.1 -> v6.4.1 field report hit: the update finished, said
    # nothing was wrong, and the operator only discovered the stack was gone when
    # their reverse proxy started serving 502s.
    if [[ "$stack_was_up" == "true" ]] && ! verify_core_running; then
        error "Update to v${new_version} completed its build, but the stack is NOT running."
        error "It was running before the update. Recover with:"
        error "    ./redamon.sh up        (or ./redamon.sh install if images are missing)"
        exit 1
    fi

    echo ""
    success "Updated to v${new_version}!"
    if [[ ${#rebuild_core[@]} -gt 0 || ${#rebuild_tools[@]} -gt 0 ]]; then
        local rebuilt_list="${rebuild_core[*]:+${rebuild_core[*]} }${rebuild_tools[*]}"
        echo -e "  ${CYAN}Rebuilt:${NC}  ${rebuilt_list}"
    fi
    if [[ ${#restart_only[@]} -gt 0 ]]; then
        echo -e "  ${CYAN}Restarted:${NC} ${restart_only[*]}"
    fi
    if [[ ${#rebuild_core[@]} -eq 0 && ${#rebuild_tools[@]} -eq 0 && ${#restart_only[@]} -eq 0 ]]; then
        info "No container images or source code needed updating."
    fi
    echo -e "  ${CYAN}Webapp:${NC}  http://localhost:3000"
    echo ""

    # Auth/db secrets are generated earlier (before the container recreate) so
    # newly-added inbound secrets take effect on this same update — see above.

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture. Order matters, and it is the reverse of what it looks
    # like: the capture pair is spawned BY THE ORCHESTRATOR, so it must be
    # reconciled AFTER the orchestrator has been recreated onto the new code, not
    # only after its own image was rebuilt.
    #
    # The early _reconcile_capture_if_running (next to the image build above)
    # refreshes the pair onto the new IMAGE, but it necessarily runs while the
    # OLD orchestrator is still serving, so the pair comes back with the old
    # SPAWN SPEC - old mounts, old env. Anything this release adds to that spec
    # (e.g. the supply-chain incident catalog mount) would be missing, silently,
    # until someone toggled capture off and on. Reconciling again here, after the
    # restarts, is what actually applies it. Idempotent and best-effort.
    _reconcile_capture_if_running
    # ...and start it if it was down (a stack recreate leaves the pair stopped).
    ensure_capture_proxy_running
}

# Populate the offline OSV database volume (supply-chain feature). Lazy and
# per-ecosystem: never downloaded at install time, only on explicit request or
# first scan. Mirrors the GVM-pull step. Runs osv-scanner's own download inside
# the analyzer image, writing into the read-only-everywhere-else osv_db volume.
cmd_supply_chain_sync() {
    local ecos="${*:-npm}"
    local analyzer_img="redamon-supply-chain-analyzer:latest"
    export_version
    if ! docker image inspect "$analyzer_img" &>/dev/null; then
        info "Supply-chain analyzer image not found, building it (first time only)..."
        if ! compose_build --profile tools build supply-chain-analyzer; then
            error "Could not build $analyzer_img. Build the tool images first: ./redamon.sh update"
            exit 1
        fi
    fi
    docker volume inspect redamon-osv-db &>/dev/null || docker volume create redamon-osv-db >/dev/null
    info "Syncing offline OSV database (ecosystems: $ecos). First npm sync is ~208 MB."
    # Runs as root: the DB volume is root-owned and read-only to every scan
    # container; the sync is the one privileged writer.
    #
    # supply_chain_common MUST be bind-mounted. It is NOT baked into the
    # analyzer image (see scanners/supply_chain_analyzer/Dockerfile - only the
    # entrypoint is COPYed); every other caller mounts it at spawn, and this
    # one did not. Without the mount the sync died with
    #   ModuleNotFoundError: No module named 'supply_chain_common'
    # which left the offline DB empty forever - and an empty DB makes every
    # supply-chain scan fail with "run './redamon.sh supply-chain-sync' first",
    # pointing at the command that could not work.
    if docker run --rm --user root \
        -v redamon-osv-db:/osv-db \
        -v "$SCRIPT_DIR/scanners/supply_chain_common:/app/supply_chain_common:ro" \
        -e OSV_SCANNER_LOCAL_DB_CACHE_DIRECTORY=/osv-db \
        -e PYTHONPATH=/app \
        --entrypoint python3 \
        "$analyzer_img" \
        -m supply_chain_common.osv_db_sync --db-path /osv-db --ecosystems "$ecos"; then
        success "OSV database sync complete."
    else
        error "OSV database sync failed."
        exit 1
    fi
}

cmd_sca_intel_sync() {
    local analyzer_img="redamon-supply-chain-analyzer:latest"
    local force=""
    [[ "${1:-}" == "--force" ]] && force="--force"
    export_version
    if ! docker image inspect "$analyzer_img" &>/dev/null; then
        info "Supply-chain analyzer image not found, building it (first time only)..."
        if ! compose_build --profile tools build supply-chain-analyzer; then
            error "Could not build $analyzer_img. Build the tool images first: ./redamon.sh update"
            exit 1
        fi
    fi
    docker volume inspect redamon-sca-intel &>/dev/null || docker volume create redamon-sca-intel >/dev/null
    info "Syncing supply-chain incident intel (supplychainattack.org, ~5 MB)."
    # Same two rules as cmd_supply_chain_sync above:
    #   --user root       the volume is root-owned and read-only to every scanner
    #   supply_chain_common bind-mount is MANDATORY - intel_sync.py is our module
    #                     and is NOT baked into the analyzer image, so without
    #                     this the run dies with ModuleNotFoundError.
    if docker run --rm --user root \
        -v redamon-sca-intel:/sca-intel \
        -v "$SCRIPT_DIR/scanners/supply_chain_common:/app/supply_chain_common:ro" \
        -e PYTHONPATH=/app \
        --entrypoint python3 \
        "$analyzer_img" \
        -m supply_chain_common.intel_sync --out /sca-intel $force; then
        success "Supply-chain incident intel sync complete."
    else
        error "Supply-chain incident intel sync failed."
        exit 1
    fi
}

ensure_tool_images() {
    local missing=false
    for img in $TOOL_IMAGES; do
        if ! docker image inspect "$img" &>/dev/null; then
            missing=true
            break
        fi
    done
    if [[ "$missing" == "true" ]]; then
        info "Tool images not found, building them (first time only)..."
        export_version
        compose_build --profile tools build
        success "Tool images built."
    fi
}

# Image tags compose would use for the core buildable services. Resolved through
# `docker compose config` rather than hardcoded, because compose derives untagged
# image names from the project name — a clone in a directory not called "redamon",
# or a COMPOSE_PROJECT_NAME override, produces different tags. Empty output means
# "could not resolve", and callers must then not block.
#
# Any leading args are passed to compose as file selectors (e.g. $DEV_COMPOSE),
# so dev mode resolves ITS overrides: dev swaps webapp for a stock node image,
# which the redamon- filter then correctly drops from the required set.
_core_image_names() {
    local files=("$@")
    # `|| true`: the script runs with pipefail, and both a compose failure and a
    # grep that matches nothing are legitimate "cannot resolve" answers here, not
    # errors to abort on. The caller treats empty output as "do not block".
    # shellcheck disable=SC2086
    docker compose ${files[@]+"${files[@]}"} config --images $CORE_BUILD_SERVICES 2>/dev/null \
        | grep '^redamon-' | sort -u || true
}

# Refuse to "start" a stack that has no images to start. Without this, `up` on a
# host whose images were wiped (a build that ran out of disk, a `docker system
# prune`) hands off to `docker compose up -d`, which silently tries to REBUILD
# everything — the same 40GB build that just failed — or exits doing nothing.
# Either way the user sees no explanation, only a 502 later.
ensure_core_images() {
    local names img missing=()
    names="$(_core_image_names "$@")"
    [[ -z "$names" ]] && return 0          # unresolvable: never block on a guess
    while IFS= read -r img; do
        [[ -z "$img" ]] && continue
        docker image inspect "$img" &>/dev/null || missing+=("$img")
    done <<< "$names"

    [[ ${#missing[@]} -eq 0 ]] && return 0

    error "Cannot start RedAmon: ${#missing[@]} core image(s) are missing."
    for img in "${missing[@]}"; do
        error "    ${img}"
    done
    error "Build them with:"
    error "    ./redamon.sh install"
    error "This is normal after a failed update or a 'docker system prune'."
    return 1
}

# True when compose reports at least one RUNNING container for <service>.
_service_running() {
    local svc="$1" ids id state
    ids="$(docker compose ps -q "$svc" 2>/dev/null)" || return 1
    [[ -n "$ids" ]] || return 1
    while IFS= read -r id; do
        [[ -z "$id" ]] && continue
        state="$(docker inspect -f '{{.State.Running}}' "$id" 2>/dev/null || echo false)"
        [[ "$state" == "true" ]] && return 0
    done <<< "$ids"
    return 1
}

# Confirm the stack is actually serving before anything announces that it is.
# `docker compose up -d` exits 0 once containers are CREATED, so a container that
# dies a second later (bad env, unwritable volume, OOM) still leaves a green exit
# code. Printing "RedAmon is ready!" over that is how a broken host stays broken:
# the operator trusts the banner and only learns otherwise from a 502 served by
# whatever proxy sits in front of :3000.
verify_core_running() {
    local failed=() svc
    for svc in webapp agent; do
        _service_running "$svc" || failed+=("$svc")
    done
    [[ ${#failed[@]} -eq 0 ]] && return 0

    error "RedAmon did not start: ${failed[*]} not running."
    error "Nothing is listening on port 3000. Diagnose with:"
    error "    docker compose ps -a"
    for svc in "${failed[@]}"; do
        error "    docker compose logs --tail 50 ${svc}"
    done
    return 1
}

cmd_up_dev() {
    _migrate_reorg_layout
    _migrate_legacy_kbase_flag
    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)

    local gvm_flag="false"
    if is_gvm_enabled; then
        gvm_flag="true"
    fi

    # shellcheck disable=SC2086
    if ! ensure_core_images $DEV_COMPOSE $GPU_COMPOSE_ARGS; then
        exit 1
    fi

    ensure_tool_images
    ensure_auth_secrets
    ensure_volume_ownership
    ensure_osv_db
    ensure_sca_intel
    ensure_db_secrets

    info "Starting RedAmon in DEV mode (GVM: ${gvm_flag})..."

    if [[ "$gvm_flag" == "true" ]]; then
        pull_gvm_images
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE $GPU_COMPOSE_ARGS up -d
    else
        # shellcheck disable=SC2086
        docker compose $DEV_COMPOSE $GPU_COMPOSE_ARGS up -d $CORE_SERVICES
    fi

    # Verify BEFORE announcing. See verify_core_running().
    if ! verify_core_running; then
        exit 1
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon DEV is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser (hot-reload)${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: start the orchestrator-spawned proxy if the master
    # switch is on (it is not compose-managed, so `up`/restart won't bring it back).
    ensure_capture_proxy_running

    # Refresh the Knowledge Base if enabled (behavior B -- always run ingest,
    # trust manifest dedup). Same rationale as cmd_up. Dev mode still benefits
    # from fresh KB on restart.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB refresh failed -- agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    fi
}

cmd_up() {
    _migrate_reorg_layout
    _migrate_legacy_kbase_flag
    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)

    local gvm_mode="false"
    if is_gvm_enabled; then
        gvm_mode="true"
    fi

    # Memory governor (Part 4): refuse to start if the host can't hold the core
    # services, and export adaptive per-service memory caps for docker-compose.
    if ! preflight_ram_gate; then
        exit 1
    fi

    # Nothing can start if nothing was ever built. Check before the tool-image
    # build below, so a wiped host is told to run `install` in one second rather
    # than after a long tool build that still leaves the core services missing.
    if ! ensure_core_images; then
        exit 1
    fi

    # Warn (never block) on a nearly-full disk: scans write into volumes, and
    # Postgres/Neo4j fail hard when the filesystem fills under them.
    local free_gb=""
    free_gb="$(_disk_free_gb "$(_docker_disk_path)")" || true
    # Proportional, not a flat 10GB: on the 500GB disk of the incident this work
    # came from, 10GB is 2% -- it would have warned only long after 97% full.
    local disk_warn_gb; disk_warn_gb="$(_disk_reserve_gb "$(_docker_disk_path)")"
    if [[ -n "$free_gb" && "$free_gb" -lt "$disk_warn_gb" ]]; then
        warn "Only ${free_gb}GB free on the Docker filesystem (want ~${disk_warn_gb}GB). Scans and the database need room."
        warn "  Reclaim space with: docker builder prune -af"
        # Below the absolute floor this stops being advisory: Postgres and Neo4j
        # fail hard when the filesystem fills under them, and a scan writing into
        # a volume is how that happens.
        if ! preflight_disk_gate "$DISK_PARTIAL_BUILD_GB" "start the stack"; then
            return 1
        fi
    fi

    export_resource_caps
    setup_zram   # optional one-time compressed-swap cushion (REDAMON_ENABLE_ZRAM=1)

    ensure_tool_images
    ensure_auth_secrets
    ensure_volume_ownership
    ensure_osv_db
    ensure_sca_intel
    ensure_db_secrets

    info "Starting RedAmon (GVM: ${gvm_mode})..."

    # Pull GVM images with retry (large images, unreliable registry)
    if [[ "$gvm_mode" == "true" ]]; then
        pull_gvm_images
    fi

    if [[ "$gvm_mode" == "true" ]]; then
        gvm_up_or_diagnose
    else
        # shellcheck disable=SC2086
        docker compose up -d $CORE_SERVICES
    fi

    # Verify BEFORE announcing. See verify_core_running().
    if ! verify_core_running; then
        exit 1
    fi

    # Show "ready" banner before the KB prompt so the user knows the app
    # is already usable (they can Ctrl+C the KB question and start working).
    echo ""
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo -e "  ${GREEN}${BOLD}  RedAmon is ready!${NC}"
    echo -e "  ${GREEN}${BOLD}  Open ${CYAN}http://localhost:3000${GREEN}${BOLD} in your browser${NC}"
    echo -e "  ${GREEN}${BOLD}==========================================================${NC}"
    echo ""

    # Ensure an admin user exists (prompts if none found)
    ensure_admin

    # HTTP Traffic Capture: start the orchestrator-spawned proxy if the master
    # switch is on (it is not compose-managed, so `up`/restart won't bring it back).
    ensure_capture_proxy_running

    # Refresh the Knowledge Base if enabled. Behavior B: always run the ingest
    # pipeline on up. The two-layer dedup (file hashes + manifest) skips
    # unchanged work, and NVD uses the `since` mechanism for incremental
    # updates -- so a routine restart is ~20-30s even though it touches the
    # network. First-ever up is ~2-3 min (full NVD fetch + embedding).
    # Fresh-clone scenario: no FAISS on disk -> full bootstrap.
    if is_kb_enabled; then
        echo ""
        local kb_profile
        kb_profile=$(_kb_choose_profile)

        if _kb_bootstrap "$kb_profile"; then
            success "Knowledge Base ready (profile: ${kb_profile})"
        else
            warn "KB refresh failed -- agent will start with the existing KB state"
            warn "Retry with: ./redamon.sh kb build ${kb_profile}"
        fi
    fi
}

cmd_down() {
    info "Stopping RedAmon..."
    # The on-demand LLM + any in-flight AI scan containers are orchestrator-spawned
    # (not compose-managed), so stop them too — otherwise the local LLM keeps
    # holding RAM after `down`.
    remove_spawned_containers
    docker compose down
    success "All services stopped. Volumes and images preserved."
}

cmd_clean() {
    warn "This will remove all RedAmon containers and images."
    warn "Your data (databases, reports, scan results) will be preserved in Docker volumes."
    echo ""
    read -rp "Continue? [y/N] " confirm
    if [[ ! "$confirm" =~ ^[Yy]$ ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers..."
    remove_spawned_containers
    docker compose --profile tools down

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    success "All RedAmon containers and images removed. Volumes preserved."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

cmd_purge() {
    echo ""
    warn "This will PERMANENTLY DELETE:"
    warn "  - All RedAmon containers and images"
    warn "  - ALL DATA: PostgreSQL, Neo4j, GVM feeds, reports, scan results"
    warn "  - Host-side KB index state (FAISS index, manifest, last-ingest marker)"
    warn "  - KB dedup state (.manifest.json, .file_hashes.json)"
    warn "  - Downloaded source files under services/knowledge_base/data/cache are PRESERVED"
    echo ""
    echo -e "${RED}${BOLD}This action cannot be undone.${NC}"
    echo ""
    read -rp "Type 'yes' to confirm: " confirm
    if [[ "$confirm" != "yes" ]]; then
        info "Cancelled."
        return
    fi

    info "Stopping containers and removing volumes..."
    # Remove orchestrator-spawned containers FIRST: the on-demand local LLM holds
    # the models volume, so `down --volumes` can't remove it until that container
    # is gone.
    remove_spawned_containers
    docker compose --profile tools down --volumes --remove-orphans
    # `compose down --volumes` only removes volumes attached to the services it
    # actually loaded, so several always survive and a "purge" silently keeps
    # data: capture_* (the proxy/ingest are orchestrator-spawned, not compose
    # services), the webapp dev caches (webapp_next_cache / webapp_node_modules
    # live in docker-compose.dev.yml, unknown to a plain `compose`), and
    # profile-gated volumes like kb_data. Sweep EVERY remaining <project>_*
    # volume by name so purge truly leaves nothing behind.
    local _proj; _proj="$(compose_project_name)"
    docker volume ls --format '{{.Name}}' 2>/dev/null \
        | grep -E "^${_proj}_" \
        | xargs -r docker volume rm >/dev/null 2>&1 || true
    # Belt-and-suspenders: explicitly drop the local-LLM models volume in case it
    # was created outside the compose lifecycle (its name is not <project>_-prefixed).
    docker volume rm "$LOCAL_LLM_VOLUME" >/dev/null 2>&1 || true
    # Networks created at RUNTIME by the orchestrator (no compose service is
    # attached to them), so `compose down` never removes them.
    docker network rm redamon-codefix-net >/dev/null 2>&1 || true
    docker network rm "${TRUFFLEHOG_NETWORK:-redamon-trufflehog-net}" >/dev/null 2>&1 || true
    # Per-run TruffleHog scratch dirs (job file + findings before publication).
    # One per project+source, so bounded — but `purge` claims to leave nothing.
    rm -rf /tmp/redamon/trufflehog_* >/dev/null 2>&1 || true

    info "Removing RedAmon images..."
    remove_redamon_images
    docker image prune -f >/dev/null 2>&1 || true

    # Host-side KB state files that must be wiped in lockstep with the
    # Neo4j volume. Leaving these behind after a purge causes a
    # split-brain on reinstall: Neo4j is empty but FAISS still has
    # stale vectors, and the dedup layers still think every chunk is
    # already ingested, so the bootstrap build becomes a no-op and
    # Neo4j stays empty.
    #
    # The on-disk content under services/knowledge_base/data/cache (tarballs,
    # CSVs, YAML templates, markdown) is deliberately preserved —
    # those are ~30+ MB of downloaded source files that don't need to
    # be re-fetched from GitHub/GitLab/NVD on every reinstall. What we
    # DO wipe are the dedup sidecars that model "what Neo4j already
    # has":
    #   - .manifest.json          (chunk-level hash dedup, Layer 2)
    #   - .file_hashes.json       (file-level hash dedup, Layer 1)
    # These live inside data/cache but are state, not content.
    info "Removing host-side KB index state..."
    # These files are created by Docker (root-owned), so normal rm may fail.
    # Try without sudo first; escalate only if needed.
    local kb_files=(
        "$SCRIPT_DIR/services/knowledge_base/data/index.faiss"
        "$SCRIPT_DIR/services/knowledge_base/data/chunk_ids.json"
        "$SCRIPT_DIR/services/knowledge_base/data/index.faiss.manifest.json"
        "$SCRIPT_DIR/services/knowledge_base/data/.last_ingest"
    )
    if ! rm -f "${kb_files[@]}" 2>/dev/null; then
        warn "Root-owned files detected, elevating with sudo..."
        # Non-fatal: a sudo-less / non-interactive run must not abort purge here
        # and leave the later volume/flag cleanup undone. Worst case these stale
        # FAISS files remain, which only matters if KB is later re-enabled.
        sudo rm -f "${kb_files[@]}" || warn "Could not remove root-owned KB index files; remove manually: sudo rm -f ${kb_files[*]}"
    fi

    info "Removing host-side KB dedup state (manifest + file hashes)..."
    if ! rm -f "$SCRIPT_DIR/services/knowledge_base/data/cache/.manifest.json" 2>/dev/null; then
        sudo rm -f "$SCRIPT_DIR/services/knowledge_base/data/cache/.manifest.json" \
            || warn "Could not remove root-owned KB manifest; remove manually with sudo."
    fi
    # Wipe every per-source .file_hashes.json without touching the
    # downloaded content alongside it. -print is for operator feedback.
    if [[ -d "$SCRIPT_DIR/services/knowledge_base/data/cache" ]]; then
        if ! find "$SCRIPT_DIR/services/knowledge_base/data/cache" \
            -type f -name '.file_hashes.json' -print -delete \
            2>/dev/null; then
            sudo find "$SCRIPT_DIR/services/knowledge_base/data/cache" \
                -type f -name '.file_hashes.json' -print -delete \
                2>/dev/null || true
        fi
    fi

    rm -f "$GVM_FLAG_FILE"
    rm -f "$KBASE_FLAG_FILE"
    rm -f "$KBASE_DISABLED_FLAG_FILE"
    rm -f "$LEGACY_SKIPKBASE_FLAG_FILE"
    rm -f "$GPU_ENABLED_FLAG_FILE" "$GPU_DISABLED_FLAG_FILE" "$TORCH_VARIANT_MARKER"
    success "Full cleanup complete. All RedAmon data and images have been removed."
    echo ""
    info "To reinstall: ./redamon.sh install"
}

# Operational memory view for `status`.
#
# WHY: status printed version, flags, KB counts and `docker compose ps` -- no
# restart counts, no OOM flag, no disk. The operator whose 502 investigation
# started this work had to run `docker inspect --format '{{.RestartCount}}'` by
# hand to find the cause. An OOM kill is the single most useful thing this
# command can tell you, so it says it.
_status_memory_report() {
    echo ""
    echo -e "  ${CYAN}Memory:${NC}"

    # The computed allocation (does not touch .env; status must stay read-only).
    if allocate_memory >/dev/null 2>&1 || [[ "${_ALLOC_TOTAL_MB:-0}" -gt 0 ]]; then
        printf '    host %sMB  |  os %sMB  services %sMB  scan pool %sMB  (burst %s%%)\n' \
            "$_ALLOC_TOTAL_MB" "$_ALLOC_OS_MB" "$_ALLOC_SERVICES_MB" "$_ALLOC_SCAN_MB" "${_ALLOC_BURST_PCT:-?}"
    fi

    local any=0 c name mem restarts oomk drift
    while read -r c; do
        [[ -z "$c" ]] && continue
        read -r mem restarts oomk <<< "$(docker inspect "$c" \
            --format '{{.HostConfig.Memory}} {{.RestartCount}} {{.State.OOMKilled}}' 2>/dev/null)"
        [[ -z "$mem" ]] && continue
        name="${c#redamon-}"
        drift=""
        # Drift: a running container whose cap differs from what we would compute
        # now. Usually means a bare `docker compose up` bypassed the governor --
        # on a deploy host that ALSO republishes ports off loopback.
        local want; want="$(_status_expected_mb "$name")"
        if [[ -n "$want" && "$mem" != "0" ]] && [[ $(( mem / 1048576 )) -ne "$want" ]]; then
            drift=" ${YELLOW}(expected ${want}MB)${NC}"
        fi
        if [[ "$oomk" == "true" ]]; then
            echo -e "    ${RED}OOM-KILLED${NC}  ${c} (cap $(( mem / 1048576 ))MB, restarts ${restarts})"
            any=1
        elif [[ "${restarts:-0}" -gt 0 ]]; then
            echo -e "    ${YELLOW}restarts=${restarts}${NC}  ${c} (cap $(( mem / 1048576 ))MB)${drift}"
            any=1
        elif [[ -n "$drift" ]]; then
            echo -e "    ${c}: $(( mem / 1048576 ))MB${drift}"
            any=1
        fi
    done <<< "$(docker ps --format '{{.Names}}' 2>/dev/null | grep '^redamon-' || true)"
    [[ "$any" -eq 0 ]] && echo -e "    ${GREEN}no OOM kills, no restarts, no cap drift${NC}"

    # Disk: the incident had 187GB used against ~70GB of images, and nothing
    # surfaced the missing ~117GB of build cache and volumes.
    local path free reserve
    path="$(_docker_disk_path)"; free="$(_disk_free_gb "$path")"
    reserve="$(_disk_reserve_gb "$path")"
    if [[ -n "$free" ]]; then
        if [[ "$free" -lt "$reserve" ]]; then
            echo -e "    ${YELLOW}disk: ${free}GB free on ${path} (want ~${reserve}GB) -- docker system df${NC}"
        else
            echo -e "    disk: ${free}GB free on ${path}"
        fi
    fi
}

# The MB this service should have, from the allocation just computed.
_status_expected_mb() {
    local svc="$1" i n=${#_ALLOC_NAMES[@]} key
    case "$svc" in
        webapp) key=WEBAPP ;; agent) key=AGENT ;; neo4j) key=NEO4J ;;
        postgres) key=POSTGRES ;; kali) key=KALI ;;
        recon-orchestrator) key=RECON_ORCHESTRATOR ;; docker-broker) key=DOCKER_BROKER ;;
        capture-proxy) key=CAPTURE_PROXY ;; traffic-ingest) key=TRAFFIC_INGEST ;;
        *) return ;;
    esac
    for (( i = 0; i < n; i++ )); do
        [[ "${_ALLOC_NAMES[$i]}" == "$key" ]] && { printf '%s' "${_ALLOC_MB[$i]}"; return; }
    done
}

# Report any CORE service that is not running. A container that exited or is
# restart-looping still resolves to nothing in Docker's embedded DNS, so the
# webapp's calls to it fail with ENOTFOUND and the operator sees an error next
# to whatever form they were filling in (issue #184). Naming the dead service
# here is the difference between a 30-second fix and a bug report.
_status_core_service_report() {
    local svc state down=() have_any=0
    for svc in $CORE_SERVICES; do
        # `ps -a --format` prints one line per container; empty means the
        # service has no container at all (never created, or removed).
        state="$(docker compose ps -a --format '{{.State}}' "$svc" 2>/dev/null | head -1)"
        [[ -n "$state" ]] && have_any=1
        [[ "$state" == "running" ]] && continue
        down+=("${svc}: ${state:-not created}")
    done

    # No container for ANY core service: this is a clone that was never
    # installed, not an outage. Calling it one would hand a new user the wrong
    # command - `up` cannot start images that were never built.
    if (( have_any == 0 )); then
        echo ""
        echo -e "  ${YELLOW}No RedAmon services are installed yet.${NC} Run: ./redamon.sh install"
        return 0
    fi

    if (( ${#down[@]} > 0 )); then
        echo ""
        echo -e "  ${RED}Core services NOT running:${NC}"
        for svc in "${down[@]}"; do
            echo -e "    ${RED}x${NC} ${svc}"
        done
        echo -e "  ${YELLOW}The webapp reaches these by container name, so while one is down the UI"
        echo -e "  fails with 'ENOTFOUND <name>'. Inspect with:${NC}"
        echo "    docker compose logs --tail=100 <service>"
        echo -e "  ${YELLOW}then bring it back with:${NC} ./redamon.sh up"
    fi
}

cmd_status() {
    _migrate_reorg_layout
    _migrate_legacy_kbase_flag

    local version
    version="$(get_version)"

    print_banner
    echo -e "  ${CYAN}Version:${NC}       v${version}"

    # GVM feature gate
    if is_gvm_enabled; then
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}GVM_ENABLED:${NC}   false"
    fi

    # PyTorch build variant, read from the FROZEN marker (not re-detected): this
    # is what the installed images actually contain. "not built yet" on a clone
    # that has never run install/update.
    local _tv
    _tv="$(cat "$TORCH_VARIANT_MARKER" 2>/dev/null)" || _tv=""
    case "$_tv" in
        gpu) echo -e "  ${CYAN}TORCH_BUILD:${NC}   ${GREEN}gpu (CUDA)${NC}" ;;
        cpu) echo -e "  ${CYAN}TORCH_BUILD:${NC}   cpu" ;;
        *)   echo -e "  ${CYAN}TORCH_BUILD:${NC}   not built yet" ;;
    esac

    # KB feature gate (from kb_config.yaml / env var)
    if is_kb_enabled; then
        echo -e "  ${CYAN}KB_ENABLED:${NC}    ${GREEN}true${NC}"
    else
        echo -e "  ${CYAN}KB_ENABLED:${NC}    false"
    fi

    # KB data state — always shown, independent of KB_ENABLED
    local faiss_count neo4j_count kb_state
    faiss_count=$(_kb_get_faiss_count)
    neo4j_count=$(_kb_get_neo4j_count)

    if [[ "$faiss_count" == "0" && "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}empty${NC}"
    elif [[ "$faiss_count" == "unknown" || "$neo4j_count" == "unknown" ]]; then
        kb_state="${YELLOW}unknown${NC}"
    elif [[ "$faiss_count" == "0" || "$neo4j_count" == "0" ]]; then
        kb_state="${YELLOW}partial${NC}"
    else
        kb_state="${GREEN}populated${NC}"
    fi
    echo -e "  ${CYAN}KB:${NC}            ${kb_state} (FAISS: ${faiss_count} vectors; NEO4J: ${neo4j_count} chunks)"

    echo ""

    # Container list — filter to redamon containers only. Keeps the header
    # row and any container whose name starts with "redamon-".
    # `-a`, not a bare `ps`: without it an EXITED core service is simply absent
    # from the table, so a crashed agent looked like a clean stack while the UI
    # failed with "getaddrinfo ENOTFOUND agent" (issue #184).
    docker compose ps -a | grep -E '^(NAME|redamon-)' || {
        # grep returns non-zero if no lines match (no containers at all).
        # Fall back to plain ps so the user still sees the "no services" message.
        docker compose ps -a
    }

    _status_core_service_report

    _status_memory_report

    # Orchestrator-spawned AI containers (NOT compose-managed, so absent above):
    # the on-demand local LLM + any in-flight AI Attack Surface scan containers.
    local spawned
    spawned=$(docker ps "${SPAWNED_CONTAINER_NAME_FILTERS[@]}" \
                --format '    {{.Names}}  ({{.Status}})' 2>/dev/null || true)
    if [[ -n "$spawned" ]]; then
        echo ""
        echo -e "  ${CYAN}AI Attack Surface (on-demand, orchestrator-spawned):${NC}"
        echo "$spawned"
    fi
}

# ---------------------------------------------------------------------------
# Knowledge Base commands
# ---------------------------------------------------------------------------

cmd_kb_build() {
    local profile="${1:-lite}"
    case "$profile" in
        cpu-lite|lite|standard|full) ;;
        *)
            error "Unknown KB profile: $profile"
            echo "Usage: ./redamon.sh kb build [lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    info "Building Knowledge Base (profile=${profile})"
    echo ""

    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)
    _kb_wait_neo4j || exit 1

    info "Running ingestion pipeline..."
    if ! _kb_make "kb-build-${profile}" MODE=docker; then
        error "KB build failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base built successfully"
    _kb_make kb-stats MODE=docker
}

cmd_kb_update() {
    local source="${1:-}"

    print_banner
    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)
    _kb_wait_neo4j || exit 1

    if [[ -n "$source" ]]; then
        case "$source" in
            nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools) ;;
            *)
                error "Unknown KB source: $source"
                echo "Valid sources: nvd, exploitdb, nuclei, gtfobins, lolbas, owasp, tools"
                exit 1
                ;;
        esac
        info "Updating KB source: ${source}"
        if ! _kb_make "kb-update-${source}" MODE=docker; then
            error "KB update failed for ${source}"
            exit 1
        fi
    else
        info "Updating all KB sources (incremental)"
        local failed=()
        for src in nvd exploitdb nuclei gtfobins lolbas owasp tools; do
            echo ""
            info "→ ${src}"
            _kb_make "kb-update-${src}" MODE=docker || failed+=("$src")
        done
        if [[ ${#failed[@]} -gt 0 ]]; then
            echo ""
            warn "Some sources failed to update: ${failed[*]}"
        fi
    fi

    echo ""
    success "Knowledge Base update complete"
    _kb_make kb-stats MODE=docker
}

cmd_kb_rebuild() {
    local profile="${1:-standard}"
    case "$profile" in
        cpu-lite|lite|standard|full) ;;
        *)
            error "Invalid profile '$profile'. Use cpu-lite, lite, standard, or full."
            echo "Usage: ./redamon.sh kb rebuild [cpu-lite|lite|standard|full]"
            exit 1
            ;;
    esac

    print_banner
    warn "This will WIPE and rebuild the entire Knowledge Base."
    info "Profile: $profile"
    echo ""

    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)
    _kb_wait_neo4j || exit 1

    info "Rebuilding Knowledge Base from scratch..."
    if ! _kb_make "kb-rebuild-${profile}" MODE=docker; then
        error "KB rebuild failed"
        exit 1
    fi

    echo ""
    success "Knowledge Base rebuilt"
    _kb_make kb-stats MODE=docker
}

cmd_kb_stats() {
    _kb_export_env
    _gpu_compose_overlay # honor the frozen GPU decision at runtime (inert on CPU)
    _kb_wait_neo4j || exit 1
    _kb_make kb-stats MODE=docker
}

cmd_kb_help() {
    echo -e "${BOLD}Usage:${NC} ./redamon.sh kb <command> [args]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}build [profile]${NC}    Build KB — profile: lite (default) | standard | full"
    echo -e "  ${GREEN}update [source]${NC}    Update KB — all sources, or one: nvd|exploitdb|nuclei|gtfobins|lolbas|owasp|tools"
    echo -e "  ${GREEN}rebuild${NC}            Wipe and rebuild (standard profile)"
    echo -e "  ${GREEN}stats${NC}              Show FAISS + Neo4j chunk counts"
    echo -e "  ${GREEN}help${NC}               Show this help"
    echo ""
    echo -e "${BOLD}Profiles:${NC}"
    echo "  lite      tool_docs + metasploit + gtfobins + lolbas + owasp + exploitdb + NVD (90 days)"
    echo "  standard  same sources as lite + NVD (2 years)"
    echo "  full      standard + Nuclei (requires redamon-kali container running)"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh kb build             # Build lite KB (default)"
    echo "  ./redamon.sh kb build standard    # Build with 2 years of NVD"
    echo "  ./redamon.sh kb rebuild           # Wipe + rebuild standard (default)"
    echo "  ./redamon.sh kb rebuild lite      # Wipe + rebuild lite profile"
    echo "  ./redamon.sh kb rebuild full      # Wipe + rebuild full profile (incl. nuclei)"
    echo "  ./redamon.sh kb update nvd        # Incremental NVD refresh"
    echo "  ./redamon.sh kb update            # Update all sources"
    echo "  ./redamon.sh kb stats             # See what's in the KB"
    echo ""
}

cmd_help() {
    print_banner
    echo -e "${BOLD}Usage:${NC} ./redamon.sh <command> [options]"
    echo ""
    echo -e "${BOLD}Commands:${NC}"
    echo -e "  ${GREEN}install${NC}              Build and start RedAmon (no GVM, no Knowledge Base)"
    echo -e "  ${GREEN}install --gvm${NC}        Build and start RedAmon (with GVM/OpenVAS)"
    echo -e "  ${GREEN}install --kbase${NC}      Build with Knowledge Base (~4.4 GB heavier, local KB enabled)"
    echo -e "  ${GREEN}install --gpu${NC}        Build the KB on CUDA PyTorch (~2.5 GB heavier; needs nvidia-container-toolkit)"
    echo -e "  ${GREEN}install --cpu${NC}        Force CPU-only PyTorch (default; auto-detected when neither flag is given)"
    echo -e "  ${GREEN}update${NC}           Pull latest version and smart-rebuild changed services"
    echo -e "  ${GREEN}up${NC}               Start services"
    echo -e "  ${GREEN}up dev${NC}           Start in dev mode (hot-reload, auto-detects GVM mode)"
    echo -e "  ${GREEN}down${NC}             Stop services (preserves data)"
    echo -e "  ${GREEN}clean${NC}            Remove containers and images (keeps data)"
    echo -e "  ${GREEN}purge${NC}            Remove everything including all data"
    echo -e "  ${GREEN}status${NC}           Show running services, version, GVM, and KB state"
    echo -e "  ${GREEN}migrate-layout${NC}   Move data left at pre-6.9 paths (runs automatically on update/up)"
    echo -e "  ${GREEN}create-admin${NC}     Create the admin login (or reset it); use if no prompt appeared at install"
    echo -e "  ${GREEN}reset-password${NC}   Reset an existing user's password"
    echo -e "  ${GREEN}kb <command>${NC}     Knowledge Base management (build/update/rebuild/stats)"
    echo -e "  ${GREEN}supply-chain-sync [ecos]${NC}  Populate the offline OSV DB (default: npm; e.g. 'npm PyPI Go')"
    echo -e "  ${GREEN}sca-intel-sync [--force]${NC}  Populate the supply-chain incident intel (supplychainattack.org)"
    echo -e "  ${GREEN}test [tier]${NC}      Run the test suite: unit (default) | integration | live | all | coverage"
    echo -e "  ${GREEN}help${NC}             Show this help message"
    echo ""
    echo -e "${BOLD}Examples:${NC}"
    echo "  ./redamon.sh install               # First-time setup (lightweight: no GVM, no KB)"
    echo "  ./redamon.sh install --kbase       # First-time setup with local Knowledge Base"
    echo "  ./redamon.sh install --gvm         # First-time setup with GVM/OpenVAS"
    echo "  ./redamon.sh install --gvm --kbase # First-time setup with everything"
    echo "  ./redamon.sh install --kbase --gpu  # Knowledge Base on the GPU (CUDA PyTorch)"
    echo "  ./redamon.sh update           # Update to latest version"
    echo "  ./redamon.sh up               # Start after reboot"
    echo "  ./redamon.sh up dev           # Dev mode with hot-reload (auto-detects GVM)"
    echo "  ./redamon.sh create-admin     # Create the admin login (or reset it)"
    echo "  ./redamon.sh reset-password   # Reset a user's password"
    echo "  ./redamon.sh kb build lite    # Build Knowledge Base"
    echo "  ./redamon.sh kb update        # Refresh all KB sources"
    echo "  ./redamon.sh kb stats         # Show KB chunk counts"
    echo ""
}

# ---------------------------------------------------------------------------
# Test runner (Part F of the testing foundation)
# ---------------------------------------------------------------------------
# One systematic entry point across every Python section. Each section runs in
# its own image with the WHOLE repo mounted at /repo (so cross-layer/sibling
# imports and git HEAD resolve), test deps runtime-installed if not already
# baked, and each test FILE isolated in its own pytest subprocess via
# tooling/scripts/pytest_isolated.py (determinism — see docs/readmes/README.TESTING.md).
# Sections whose image is absent are skipped cleanly.
#
#   ./redamon.sh test              # unit gate across all sections (canonical)
#   ./redamon.sh test unit|integration|live|all|coverage
#
# The root `tests/` dir is a grab-bag: most files exercise the agent image, but a
# set of them import recon enrichment modules (recon/main_recon_modules/*) and so
# must run in the recon image, not the agent image. We route them explicitly.
_ROOT_RECON_TESTS="test_censys_enrich.py,test_criminalip_enrich.py,test_fofa_enrich.py,test_netlas_enrich.py,test_otx_enrich.py,test_uncover_enrich.py,test_virustotal_enrich.py,test_zoomeye_enrich.py,test_gau_parallel.py,test_gau_urlscan_api_key.py,test_recon_mixin_split.py,test_custom_templates_integration.py,test_masscan_integration.py"

# Section spec: name|image|workdir|PYTHONPATH|testpaths|covpkg|exclude
_TEST_SECTIONS=(
    "agent|redamon-agent|/repo/agentic|/repo/agentic:/repo:/repo/mcp/servers:/repo/recon_orchestrator:/repo/services|tests|.|"
    "root-agent|redamon-agent|/repo|/repo:/repo/agentic:/repo/mcp/servers:/repo/services:/repo/scanners|tests scanners/supply_chain_common scanners/supply_chain_analyzer scanners/supply_chain_scan graph_db services/knowledge_base mcp|supply_chain_common|${_ROOT_RECON_TESTS}"
    "root-recon|redamon-recon|/repo|/repo:/repo/recon:/repo/recon/main_recon_modules|tests|.|"
    "recon|redamon-recon|/repo/recon|/repo/recon:/repo|tests|.|"
    "recon_orchestrator|redamon-recon-orchestrator|/repo/recon_orchestrator|/repo/recon_orchestrator:/repo|.|.|"
    "ai_attack_surface|redamon-ai-attack-surface|/repo/scanners/ai_attack_surface_scan|/repo/scanners/ai_attack_surface_scan:/repo|tests adapters|.|"
    "capture_proxy|redamon-capture-proxy|/repo/scanners/capture_proxy|/repo/scanners/capture_proxy:/repo|tests|.|"
    "docker_broker|redamon-docker-broker|/repo/services/docker_broker|/repo/services/docker_broker:/repo|.|.|"
)

# For the root-recon section we run ONLY the recon-oriented files, not the whole
# tests/ tree. The runner passes them as explicit files when name == root-recon.
_ROOT_RECON_PATHS=""
for _f in ${_ROOT_RECON_TESTS//,/ }; do _ROOT_RECON_PATHS="$_ROOT_RECON_PATHS tests/$_f"; done

_test_run_section() {
    local name="$1" image="$2" workdir="$3" pypath="$4" testpaths="$5" covpkg="$6" exclude="$7"
    local tier="$8"
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        warn "SKIP section '$name' ($image not built)"
        return 0
    fi
    # root-recon runs ONLY the recon-oriented files from tests/, in the recon image.
    if [[ "$name" == "root-recon" ]]; then
        testpaths="$_ROOT_RECON_PATHS"
    fi
    info "=== section: $name  (image: $image, tier: $tier) ==="
    local cov_args=""
    if [[ "$tier" == "coverage" ]]; then
        cov_args="--cov $covpkg --cov-floor ${REDAMON_COV_FLOOR:-0}"
        tier="all"
    fi
    [[ -n "$exclude" ]] && cov_args="$cov_args --exclude $exclude"
    # Ensure pytest is available (baked in the daily images; runtime-installed
    # for the slim ones), silence git's dubious-ownership guard on the mount.
    local prep='python -c "import pytest" 2>/dev/null || pip install -q -r /repo/requirements-test.txt >/dev/null 2>&1; git config --global --add safe.directory "*" 2>/dev/null || true;'
    docker run --rm \
        -v "$SCRIPT_DIR:/repo" \
        -w "$workdir" \
        -e PYTHONPATH="$pypath" \
        -e COVERAGE_FILE=/tmp/redamon.coverage \
        -e HOME=/tmp \
        -e REDAMON_TEST_PARALLEL="${REDAMON_TEST_PARALLEL:-8}" \
        `# recon_orchestrator/api.py resolves host paths at import; satisfy the` \
        `# *_PATH lookups so its tests import outside docker-compose (harmless elsewhere).` \
        -e RECON_PATH=/repo/recon \
        -e GVM_SCAN_PATH=/repo/scanners/gvm_scan \
        -e GITHUB_HUNT_PATH=/repo/scanners/github_secret_hunt \
        -e TRUFFLEHOG_PATH=/repo/scanners/trufflehog_scan \
        -e SUPPLY_CHAIN_PATH=/repo/scanners/supply_chain_scan \
        -e GRAPH_DB_PATH=/repo/graph_db \
        -e AI_ATTACK_SURFACE_PATH=/repo/scanners/ai_attack_surface_scan \
        -e CUSTOM_TEMPLATES_PATH=/repo/custom_templates \
        -e CODEFIX_WORK_PATH=/repo/scanners/codefix_sandbox \
        --entrypoint sh \
        "$image" -c "$prep exec python /repo/tooling/scripts/pytest_isolated.py $tier $testpaths $cov_args"
}

cmd_test() {
    local tier="${1:-unit}"
    case "$tier" in
        unit|integration|live|all|coverage) ;;
        *) error "Unknown test tier: $tier (use unit|integration|live|all|coverage)"; return 2 ;;
    esac
    local failed=0 spec
    for spec in "${_TEST_SECTIONS[@]}"; do
        IFS='|' read -r name image workdir pypath testpaths covpkg exclude <<< "$spec"
        if ! _test_run_section "$name" "$image" "$workdir" "$pypath" "$testpaths" "$covpkg" "$exclude" "$tier"; then
            failed=1
            error "section '$name' had failures"
        fi
    done
    echo
    if [[ $failed -eq 0 ]]; then
        success "ALL TEST SECTIONS GREEN (tier: $tier)"
    else
        error "TEST FAILURES ABOVE (tier: $tier)"
    fi
    # Shell (bash) — the redamon.sh/deploy logic the Python sections cannot reach.
    # Same tiers as webapp: these suites are hermetic, so they belong in the gate.
    if [[ "$tier" == "all" || "$tier" == "coverage" || "$tier" == "unit" ]]; then
        _test_run_shell || failed=1
    fi
    # Webapp (vitest) — only for the broader tiers; needs node_modules.
    if [[ "$tier" == "all" || "$tier" == "coverage" || "$tier" == "unit" ]]; then
        _test_run_webapp "$tier" || failed=1
    fi
    return $failed
}

# Bash suites for the parts of the system written in shell: the memory allocator,
# the preflight gates, secret/admin handling and the deploy driver. They exercise
# redamon.sh itself (sourcing it — the BASH_SOURCE guard at the bottom stops the
# dispatch from firing), so they need no image and run on the host.
#
# Every suite here MUST be hermetic or self-skip: any that needs a live stack
# (e.g. scan_timeline_db_test.sh without postgres) exits 0 with a SKIP line.
# Files named *_smoke.sh / *_live.sh are deliberately NOT matched by the glob.
_test_run_shell() {
    local files=("$SCRIPT_DIR"/tests/*_test.sh)
    if [[ ! -e "${files[0]}" ]]; then
        warn "SKIP shell suites (no tests/*_test.sh found)"
        return 0
    fi
    info "=== section: shell (bash) ==="
    local f name rc shell_failed=0 passed=0
    for f in "${files[@]}"; do
        name="$(basename "$f")"
        if bash "$f" >/dev/null 2>&1; then
            rc=0
        else
            rc=$?
        fi
        if [[ $rc -eq 0 ]]; then
            passed=$(( passed + 1 ))
            echo -e "  ${GREEN}ok${NC}    $name"
        else
            shell_failed=1
            echo -e "  ${RED}FAIL${NC}  $name (exit $rc) — re-run: bash tests/$name"
        fi
    done
    if [[ $shell_failed -eq 0 ]]; then
        success "shell suites: ${passed} file(s) green"
    else
        error "shell suites: failures above"
    fi
    return $shell_failed
}

_test_run_webapp() {
    local tier="$1"
    if [[ ! -x "$SCRIPT_DIR/webapp/node_modules/.bin/vitest" ]]; then
        warn "SKIP webapp vitest (webapp/node_modules absent; run in the webapp image or 'npm ci')"
        return 0
    fi
    info "=== section: webapp (vitest) ==="
    if [[ "$tier" == "coverage" ]]; then
        ( cd "$SCRIPT_DIR/webapp" && npm run test:coverage )
    else
        ( cd "$SCRIPT_DIR/webapp" && npm run test )
    fi
}

# Containers whose SERVICE has been removed from docker-compose.yml. Compose never
# deletes those: it leaves them behind and prints "Found orphan containers" on every
# single `up`. Removing them by name keeps an upgraded install as clean as a fresh
# one. Only ever list containers that are inert by construction.
#   redamon-gvm-postgres-init: its stale-lock cleanup moved INTO gvm-postgres'
#   own entrypoint, because as a sibling one-shot it deleted the LIVE socket on
#   every repeat `up` and left gvmd crash-looping (issue #174).
_REMOVED_CONTAINERS=(redamon-gvm-postgres-init)

prune_removed_containers() {
    command -v docker >/dev/null 2>&1 || return 0
    local existing c
    existing="$(docker ps -a --format '{{.Names}}' 2>/dev/null)" || return 0
    for c in "${_REMOVED_CONTAINERS[@]}"; do
        if printf '%s\n' "$existing" | grep -qx "$c"; then
            docker rm -f "$c" >/dev/null 2>&1 \
                && info "Removed obsolete container $c (its service no longer exists)"
        fi
    done
    return 0
}


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

# Dispatch only when executed directly. When the script is sourced (e.g. by the
# test suite in tests/redamon_build_test.sh) this guard prevents the cd and the
# command dispatch from running, so the helper functions can be loaded and unit-
# tested in isolation.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
cd "$SCRIPT_DIR"

# #163: clamp the per-service `cpus:` caps to the host's core count for EVERY
# command that can touch Docker. Done here rather than inside each command
# because `install`, `update` and the password/KB helpers all reach
# `docker compose up` by different routes, and any one of them exceeding the
# core count aborts the whole `up`. `help` is excluded so it stays offline.
case "${1:-help}" in
    help|--help|-h) ;;
    *) export_cpu_caps ;;
esac

# Memory allocation, for EVERY command that can create or recreate a container.
# Same reasoning as the CPU clamp above, and it must be here rather than inside
# each command because they reach `docker compose up` by different routes:
#   - `install` ends in `docker compose up -d --force-recreate`, so without this
#     a FRESH install created every container with the compose fallbacks and
#     wrote no .env block at all -- the allocation only appeared after the first
#     later `up`.
#   - `up dev` (cmd_up_dev) never called it either.
#   - `update` called it only when docker-compose.yml itself had changed, so a
#     release that touched only source, or a host that had been RESIZED, kept the
#     previous allocation.
# Running it here also means the .env block is written BEFORE any `docker compose
# up` in those commands reads it.
case "${1:-help}" in
    install|update|up) export_resource_caps; prune_removed_containers ;;
esac

case "${1:-help}" in
    install) shift; cmd_install "$@" ;;
    update)  shift; cmd_update "$@" ;;
    up)
        if [[ "${2:-}" == "dev" ]]; then
            cmd_up_dev
        else
            cmd_up
        fi
        ;;
    down)    cmd_down ;;
    migrate-layout)
        # Re-run the pre-6.9 layout migration on its own. Normally it runs
        # automatically from update/up/status; run it explicitly (optionally
        # under sudo) when container-written, root-owned files were left behind.
        _REORG_MOVED=0
        _migrate_reorg_layout
        [[ "${_REORG_MOVED:-0}" -eq 0 ]] && success "Layout is already up to date; nothing to migrate."
        ;;
    clean)   cmd_clean ;;
    purge)   cmd_purge ;;
    status)  cmd_status ;;
    kb)
        shift
        case "${1:-help}" in
            build)   shift; cmd_kb_build   "${1:-lite}" ;;
            update)  shift; cmd_kb_update  "${1:-}" ;;
            rebuild) shift; cmd_kb_rebuild "${1:-standard}" ;;
            stats)   cmd_kb_stats ;;
            help|--help|-h|"") cmd_kb_help ;;
            *)
                error "Unknown kb command: $1"
                cmd_kb_help
                exit 1
                ;;
        esac
        ;;
    reset-password) cmd_reset_password ;;
    create-admin)   cmd_create_admin ;;
    supply-chain-sync) shift; cmd_supply_chain_sync "$@" ;;
    sca-intel-sync) shift; cmd_sca_intel_sync "$@" ;;
    test)           shift; cmd_test "${1:-unit}" ;;
    help|--help|-h) cmd_help ;;
    *)
        error "Unknown command: $1"
        cmd_help
        exit 1
        ;;
esac
fi
