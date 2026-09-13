#!/usr/bin/env bash
set -euo pipefail
source "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/redamon.sh"
marker=$(mktemp)
trap 'rm -f "$marker"' EXIT
printf 'gpu\n' > "$marker"
TORCH_VARIANT_MARKER="$marker"
gpu_runtime_available() { return 0; }
cygpath() { printf 'E:/Fixture Repo%s\n' "${2#/fixture}"; }
SCRIPT_DIR=/fixture
OSTYPE=msys
unset COMPOSE_FILE COMPOSE_PATH_SEPARATOR
_gpu_compose_overlay
[[ "$COMPOSE_FILE" == 'E:/Fixture Repo/docker-compose.yml;E:/Fixture Repo/docker-compose.gpu.yml' ]]
previous="$COMPOSE_FILE"
_gpu_compose_overlay
[[ "$COMPOSE_FILE" == "$previous" ]]
OSTYPE=linux-gnu
unset COMPOSE_FILE COMPOSE_PATH_SEPARATOR
_gpu_compose_overlay
[[ "$COMPOSE_FILE" == '/fixture/docker-compose.yml:/fixture/docker-compose.gpu.yml' ]]
COMPOSE_FILE=/custom.yml
COMPOSE_PATH_SEPARATOR='|'
_gpu_compose_overlay
[[ "$COMPOSE_FILE" == '/custom.yml|/fixture/docker-compose.gpu.yml' ]]
docker() { printf 'fixture compose failure\n' >&2; return 2; }
if output=$(pull_gvm_images 2>&1); then
    printf 'Expected Compose failure\n' >&2
    exit 1
fi
[[ "$output" == *'fixture compose failure'* ]]
printf 'GPU Compose path and error regressions passed\n'
