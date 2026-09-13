#!/usr/bin/env bash
# =============================================================================
# Test suite for the build-time CPU/GPU PyTorch variant decision in redamon.sh
# (gpu_runtime_available / is_gpu_enabled / _gpu_export_env / _gpu_compose_overlay)
# plus the Dockerfile + compose contracts that carry the decision.
#
# The feature: `pip install torch` resolves to the CUDA wheel by default, adding
# ~2.5 GB of unused nvidia-* runtime PER install site. The variant is decided
# ONCE at build time, frozen into `.torch-variant`, and every later command obeys
# that marker instead of re-probing the hardware.
#
# Suites: unit (stubbed docker), regression (one per bug found in review),
#         contract (Dockerfile/compose invariants). Run:
#   bash tests/redamon_gpu_torch_test.sh
# No Docker daemon required: `docker` is stubbed throughout.
# =============================================================================
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# shellcheck disable=SC1090
source "$REPO_ROOT/redamon.sh"
set +e

PASS=0; FAIL=0
pass() { PASS=$((PASS+1)); printf '  \033[0;32mPASS\033[0m %s\n' "$1"; }
fail() { FAIL=$((FAIL+1)); printf '  \033[0;31mFAIL\033[0m %s\n' "$1"; }
assert_eq() { if [[ "$2" == "$3" ]]; then pass "$1"; else fail "$1 (got='$2' expected='$3')"; fi; }
assert_contains() { if [[ "$2" == *"$3"* ]]; then pass "$1"; else fail "$1 (missing '$3' in: $2)"; fi; }
assert_not_contains() { if [[ "$2" != *"$3"* ]]; then pass "$1"; else fail "$1 (unexpected '$3' in: $2)"; fi; }
# NOTE: label is $1 and MUST be shifted off before running the command, or the
# label itself is executed (an unknown command "fails", making assert_false pass
# for the wrong reason -- a false green).
assert_true()  { local l="$1"; shift; if "$@" >/dev/null 2>&1; then pass "$l -> true"; else fail "$l (expected true)"; fi; }
assert_false() { local l="$1"; shift; if "$@" >/dev/null 2>&1; then fail "$l (expected false)"; else pass "$l -> false"; fi; }
section() { printf '\n\033[1m== %s ==\033[0m\n' "$1"; }

# --- isolation: never touch the developer's real flag files -------------------
# The globals are set from $SCRIPT_DIR at source time; repoint them at a sandbox
# so a test run cannot flip the machine's actual build variant.
TESTDIR="$(mktemp -d)"
trap 'rm -rf "$TESTDIR"' EXIT
GPU_ENABLED_FLAG_FILE="$TESTDIR/.gpu-enabled"
GPU_DISABLED_FLAG_FILE="$TESTDIR/.gpu-disabled"
TORCH_VARIANT_MARKER="$TESTDIR/.torch-variant"

reset_state() {
    rm -f "$GPU_ENABLED_FLAG_FILE" "$GPU_DISABLED_FLAG_FILE" "$TORCH_VARIANT_MARKER"
    unset COMPOSE_FILE TORCH_INDEX_URL TORCH_CUDA_INDEX_URL
    GPU_COMPOSE_ARGS=""
    WARNINGS=""
}

# Capture warn/info instead of printing (assertions read WARNINGS).
WARNINGS=""
info() { :; }
warn() { WARNINGS+="$* "; }

# --- docker stub -------------------------------------------------------------
# NVIDIA_RUNTIME=1 -> the daemon reports an nvidia runtime key.
# DOCKER_BROKEN=1  -> `docker info` fails (daemon down).
NVIDIA_RUNTIME=0
DOCKER_BROKEN=0
docker() {
    if [[ "${1:-}" == "info" ]]; then
        [[ "$DOCKER_BROKEN" == "1" ]] && return 1
        if [[ "$NVIDIA_RUNTIME" == "1" ]]; then
            echo "io.containerd.runc.v2 nvidia runc "
        else
            echo "io.containerd.runc.v2 runc "
        fi
        return 0
    fi
    return 0
}

# nvidia-smi stub: SMI_PRESENT=1 installs the binary, SMI_WORKS decides whether
# it actually talks to a driver.
SMI_PRESENT=0
SMI_WORKS=0
command() {
    if [[ "${1:-}" == "-v" && "${2:-}" == "nvidia-smi" ]]; then
        [[ "$SMI_PRESENT" == "1" ]] && { echo /usr/bin/nvidia-smi; return 0; }
        return 1
    fi
    builtin command "$@"
}
nvidia-smi() { [[ "$SMI_WORKS" == "1" ]]; }

# =============================================================================
section "unit: gpu_runtime_available (detect the RUNTIME, not the card)"
# =============================================================================
reset_state; NVIDIA_RUNTIME=1; SMI_PRESENT=0; SMI_WORKS=0; DOCKER_BROKEN=0
assert_true "nvidia among docker runtime keys" gpu_runtime_available

reset_state; NVIDIA_RUNTIME=0; SMI_PRESENT=0; SMI_WORKS=0
assert_false "no nvidia runtime and no nvidia-smi" gpu_runtime_available

# REGRESSION: the first implementation used a bare `command -v nvidia-smi`, so a
# host with the binary but a DEAD driver (exactly this dev box) was misdetected
# as GPU-capable and would have built a 2.5 GB CUDA image that can never run.
reset_state; NVIDIA_RUNTIME=0; SMI_PRESENT=1; SMI_WORKS=0
assert_false "regression: nvidia-smi binary present but driver dead" gpu_runtime_available

reset_state; NVIDIA_RUNTIME=0; SMI_PRESENT=1; SMI_WORKS=1
assert_true "nvidia-smi present AND working (driver fallback)" gpu_runtime_available

# Daemon down must not be read as "GPU present".
reset_state; DOCKER_BROKEN=1; SMI_PRESENT=0; SMI_WORKS=0
assert_false "docker daemon down and no smi" gpu_runtime_available
DOCKER_BROKEN=0

# =============================================================================
section "unit: is_gpu_enabled (explicit flag beats detection)"
# =============================================================================
reset_state; NVIDIA_RUNTIME=0; SMI_PRESENT=0
touch "$GPU_ENABLED_FLAG_FILE"
assert_true  "--gpu flag forces GPU even with no runtime" is_gpu_enabled

reset_state; NVIDIA_RUNTIME=1
touch "$GPU_DISABLED_FLAG_FILE"
assert_false "--cpu flag forces CPU even with a runtime" is_gpu_enabled

reset_state; NVIDIA_RUNTIME=1
assert_true  "no flags -> auto-detect (runtime present)" is_gpu_enabled

reset_state; NVIDIA_RUNTIME=0
assert_false "no flags -> auto-detect (no runtime)" is_gpu_enabled

# Both markers should never coexist (cmd_install rm -f's the other), but the
# precedence must still be deterministic rather than filesystem-order dependent.
reset_state; NVIDIA_RUNTIME=0
touch "$GPU_ENABLED_FLAG_FILE" "$GPU_DISABLED_FLAG_FILE"
assert_true "both markers present -> enabled wins (deterministic)" is_gpu_enabled

# =============================================================================
section "unit: _gpu_export_env (freeze the decision)"
# =============================================================================
reset_state; NVIDIA_RUNTIME=0
_gpu_export_env
assert_contains "CPU build exports the CPU index" "$TORCH_INDEX_URL" "/whl/cpu"
assert_eq       "CPU build writes marker=cpu" "$(cat "$TORCH_VARIANT_MARKER")" "cpu"

reset_state; NVIDIA_RUNTIME=1
_gpu_export_env
assert_contains "GPU build exports a CUDA index" "$TORCH_INDEX_URL" "/whl/cu"
assert_eq       "GPU build writes marker=gpu" "$(cat "$TORCH_VARIANT_MARKER")" "gpu"

reset_state; NVIDIA_RUNTIME=1
export TORCH_CUDA_INDEX_URL="https://download.pytorch.org/whl/cu118"
_gpu_export_env
assert_eq "TORCH_CUDA_INDEX_URL override is honored" "$TORCH_INDEX_URL" "https://download.pytorch.org/whl/cu118"
unset TORCH_CUDA_INDEX_URL

# Marker is the source of truth for every later command, so a failed write must
# be loud, not swallowed (it would silently drop GPU device access).
reset_state; NVIDIA_RUNTIME=1
TORCH_VARIANT_MARKER="$TESTDIR/nonexistent-dir/.torch-variant"
_gpu_export_env
assert_contains "regression: unwritable marker warns instead of failing silently" "$WARNINGS" "Could not write"
TORCH_VARIANT_MARKER="$TESTDIR/.torch-variant"

# =============================================================================
section "unit: _gpu_compose_overlay (obey the frozen marker)"
# =============================================================================
reset_state; NVIDIA_RUNTIME=1
printf 'cpu' > "$TORCH_VARIANT_MARKER"
_gpu_compose_overlay
assert_eq "CPU marker -> COMPOSE_FILE untouched" "${COMPOSE_FILE:-unset}" "unset"
assert_eq "CPU marker -> no compose args"        "$GPU_COMPOSE_ARGS" ""

reset_state; NVIDIA_RUNTIME=1
_gpu_compose_overlay   # no marker at all (fresh clone)
assert_eq "missing marker -> inert" "${COMPOSE_FILE:-unset}" "unset"

reset_state; NVIDIA_RUNTIME=1
printf 'gpu' > "$TORCH_VARIANT_MARKER"
_gpu_compose_overlay
assert_contains "GPU marker -> overlay in COMPOSE_FILE" "${COMPOSE_FILE:-}" "docker-compose.gpu.yml"
assert_contains "GPU marker -> overlay in compose args" "$GPU_COMPOSE_ARGS" "docker-compose.gpu.yml"
assert_contains "GPU marker -> base compose file kept"  "${COMPOSE_FILE:-}" "docker-compose.yml"

# REGRESSION (B4): relative paths break any call site that runs from another cwd.
expected_overlay="$REPO_ROOT/docker-compose.gpu.yml"
case "$OSTYPE" in msys*|cygwin*) expected_overlay=$(cygpath -m "$expected_overlay") ;; esac
assert_contains "regression: overlay uses an absolute path" "${COMPOSE_FILE:-}" "$expected_overlay"

# REGRESSION (B5): cmd_install calls the overlay, then _kb_bootstrap calls it
# again in the SAME process. A non-idempotent append duplicates the file entry.
reset_state; NVIDIA_RUNTIME=1
printf 'gpu' > "$TORCH_VARIANT_MARKER"
_gpu_compose_overlay
_gpu_compose_overlay
_gpu_compose_overlay
occurrences=$(grep -o "docker-compose.gpu.yml" <<<"${COMPOSE_FILE:-}" | wc -l | tr -d ' ')
assert_eq "regression: repeated calls stay idempotent" "$occurrences" "1"

# A user-supplied COMPOSE_FILE must be extended, never replaced.
reset_state; NVIDIA_RUNTIME=1
printf 'gpu' > "$TORCH_VARIANT_MARKER"
export COMPOSE_FILE="custom.yml"
_gpu_compose_overlay
assert_contains "pre-existing COMPOSE_FILE is preserved" "$COMPOSE_FILE" "custom.yml"
assert_contains "pre-existing COMPOSE_FILE is extended"  "$COMPOSE_FILE" "docker-compose.gpu.yml"

# REGRESSION (B3): the build decision is frozen, but the hardware can vanish
# (driver upgrade, toolkit removed, image moved to another host). Requesting an
# nvidia device the daemon cannot provide makes `up` fail hard and leaves the
# WHOLE stack unstartable. Must degrade to CPU with a warning instead.
reset_state; NVIDIA_RUNTIME=0; SMI_PRESENT=0
printf 'gpu' > "$TORCH_VARIANT_MARKER"
_gpu_compose_overlay
assert_eq       "regression: stale GPU marker + no runtime -> no device request" "${COMPOSE_FILE:-unset}" "unset"
assert_contains "regression: stale GPU marker warns the operator" "$WARNINGS" "WITHOUT GPU access"
assert_contains "regression: stale GPU marker suggests the fix"   "$WARNINGS" "install --cpu"

# =============================================================================
section "contract: compose wiring"
# =============================================================================
gpu_yml="$REPO_ROOT/docker-compose.gpu.yml"
[[ -f "$gpu_yml" ]] && pass "docker-compose.gpu.yml exists" || fail "docker-compose.gpu.yml missing"

gpu_body="$(cat "$gpu_yml" 2>/dev/null)"
assert_contains "overlay grants an nvidia device" "$gpu_body" "driver: nvidia"
assert_contains "overlay targets the agent"       "$gpu_body" "agent:"
# The overlay must not touch the scanner: it is CPU-only by design, and a device
# reservation there would fail `up` for no benefit.
assert_not_contains "overlay does NOT touch ai-attack-surface" "$gpu_body" "ai-attack-surface"

compose_body="$(cat "$REPO_ROOT/docker-compose.yml")"
assert_contains "agent build passes TORCH_INDEX_URL" "$compose_body" "TORCH_INDEX_URL:"
# The DEFAULT must be CPU: an unset env var is the common case (bare
# `docker compose build`, CI, a contributor who never runs redamon.sh).
default_line="$(grep -c 'TORCH_INDEX_URL: "${TORCH_INDEX_URL:-https://download.pytorch.org/whl/cpu}"' <<<"$compose_body")"
assert_eq "both agent build blocks default to the CPU index" "$default_line" "2"

# =============================================================================
section "contract: Dockerfile pins"
# =============================================================================
scanner_df="$(cat "$REPO_ROOT/scanners/ai_attack_surface_scan/Dockerfile")"
for venv in garak pyrit giskard; do
    n="$(grep -c "/opt/venv-$venv/bin/pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu" <<<"$scanner_df")"
    assert_eq "scanner venv '$venv' is pinned to the CPU wheel" "$n" "1"
done
assert_contains "scanner has the CPU-variant build guard" "$scanner_df" "torch CPU-variant guard"
# The scanner is deliberately CPU-only: it must NOT accept a CUDA index.
assert_not_contains "scanner is not parametrized for CUDA" "$scanner_df" "whl/cu"

agent_df="$(cat "$REPO_ROOT/agentic/Dockerfile")"
assert_contains "agent declares the TORCH_INDEX_URL build arg" "$agent_df" "ARG TORCH_INDEX_URL"
assert_contains "agent defaults that arg to the CPU index"     "$agent_df" "ARG TORCH_INDEX_URL=https://download.pytorch.org/whl/cpu"
assert_contains "agent pre-installs torch from that index"     "$agent_df" 'pip install --no-cache-dir torch --index-url "$TORCH_INDEX_URL"'
assert_contains "agent has the variant guard"                  "$agent_df" "TORCH_INDEX_URL asked for"
# A build-only knob must not be baked into the runtime image.
assert_not_contains "agent does not bake TORCH_INDEX_URL as ENV" "$agent_df" "ENV TORCH_INDEX_URL"

# =============================================================================
section "regression: dev mode must carry the overlay (B2)"
# =============================================================================
# `docker compose -f a -f b` IGNORES $COMPOSE_FILE entirely, so the dev path
# (which passes its own -f flags via $DEV_COMPOSE) would silently start a
# CUDA-built agent with NO GPU access. Every dev call site must append
# $GPU_COMPOSE_ARGS.
redamon_body="$(cat "$REPO_ROOT/redamon.sh")"
# The pattern matches call sites only: the definition line carries no `$`, and
# the two prose mentions are followed by ')'.
dev_uses=$(grep -cE '\$DEV_COMPOSE( |$)' <<<"$redamon_body")
dev_with_gpu=$(grep -cE '\$DEV_COMPOSE \$GPU_COMPOSE_ARGS' <<<"$redamon_body")
[[ "$dev_uses" -ge 3 ]] && pass "found $dev_uses \$DEV_COMPOSE call sites to check" \
                        || fail "expected >=3 \$DEV_COMPOSE call sites, found $dev_uses"
assert_eq "regression: every \$DEV_COMPOSE compose call carries \$GPU_COMPOSE_ARGS" \
          "$dev_with_gpu" "$dev_uses"

# =============================================================================
section "unit: overlay re-exports the FROZEN build arg (update/up consistency)"
# =============================================================================
# Any build reached from a runtime command must reproduce the variant this
# install was BUILT with, not fall back to the compose default.
reset_state; NVIDIA_RUNTIME=1
printf 'gpu' > "$TORCH_VARIANT_MARKER"
_gpu_compose_overlay
assert_contains "gpu marker re-exports a CUDA index" "${TORCH_INDEX_URL:-}" "/whl/cu"

reset_state; NVIDIA_RUNTIME=1
printf 'cpu' > "$TORCH_VARIANT_MARKER"
_gpu_compose_overlay
assert_eq "cpu marker re-exports the CPU index" "${TORCH_INDEX_URL:-}" "https://download.pytorch.org/whl/cpu"

reset_state; NVIDIA_RUNTIME=1
_gpu_compose_overlay   # no marker
assert_eq "no marker -> build arg left to the compose default" "${TORCH_INDEX_URL:-unset}" "unset"

# =============================================================================
section "contract: lifecycle subcommands (install/update/purge/status)"
# =============================================================================
# purge means "remove everything": a surviving .gpu-enabled would force the NEXT
# install onto a variant the user never asked for.
purge_body="$(sed -n '/^cmd_purge()/,/^}/p' "$REPO_ROOT/redamon.sh")"
assert_contains "purge clears the GPU flag markers"  "$purge_body" "GPU_ENABLED_FLAG_FILE"
assert_contains "purge clears the frozen variant"    "$purge_body" "TORCH_VARIANT_MARKER"

update_body="$(sed -n '/^cmd_update()/,/^}/p' "$REPO_ROOT/redamon.sh")"
assert_contains "update accepts --gpu"                "$update_body" "--gpu)"
assert_contains "update accepts --cpu"                "$update_body" "--cpu)"
# The re-exec hands control to the freshly-pulled script; without forwarding, an
# explicit --gpu would be silently dropped mid-update.
assert_contains "update forwards its flags across the re-exec" "$update_body" 'update ${update_args[@]+"${update_args[@]}"}'
# Unlike install, update must NOT reset the sticky choice when no flag is given.
noflag_reset=$(grep -c 'rm -f "$GPU_ENABLED_FLAG_FILE" "$GPU_DISABLED_FLAG_FILE"' <<<"$update_body")
assert_eq "update never clears both markers (preserves the install choice)" "$noflag_reset" "0"
# install DOES reset to auto-detect when no flag is given.
install_body="$(sed -n '/^cmd_install()/,/^}/p' "$REPO_ROOT/redamon.sh")"
assert_contains "install resets to auto-detect with no flag" "$install_body" 'rm -f "$GPU_ENABLED_FLAG_FILE" "$GPU_DISABLED_FLAG_FILE"'
# The build arg must be exported BEFORE any image is built.
for fn in cmd_install cmd_update; do
    body="$(sed -n "/^$fn()/,/^}/p" "$REPO_ROOT/redamon.sh")"
    exp_line=$(grep -n "_gpu_export_env" <<<"$body" | head -1 | cut -d: -f1)
    bld_line=$(grep -n "compose_build" <<<"$body" | head -1 | cut -d: -f1)
    if [[ -n "$exp_line" && -n "$bld_line" && "$exp_line" -lt "$bld_line" ]]; then
        pass "$fn exports the build arg before building (line $exp_line < $bld_line)"
    else
        fail "$fn: _gpu_export_env(@$exp_line) must precede compose_build(@$bld_line)"
    fi
done

status_body="$(sed -n '/^cmd_status()/,/^}/p' "$REPO_ROOT/redamon.sh")"
assert_contains "status reports the frozen build variant" "$status_body" "TORCH_BUILD"

# update must rebuild BOTH images this feature touches.
assert_contains "update rebuilds the agent on agentic/ changes"  "$update_body" 'grep -q "^agentic/"'
assert_contains "update rebuilds the scanner on its Dockerfile"  "$update_body" 'scanners/ai_attack_surface_scan/(Dockerfile'

# =============================================================================
printf '\n\033[1m== SUMMARY ==\033[0m\n'
printf '  PASS: %-4s FAIL: %s\n' "$PASS" "$FAIL"
[[ "$FAIL" -eq 0 ]] || exit 1
exit 0
