#!/usr/bin/env bash
# ============================================================================
#  RedAmon single-host cloud deploy driver
# ----------------------------------------------------------------------------
#  Thin REMOTE DRIVER around the repo's own redamon.sh: prepare a bare Linux host,
#  get the repo onto it, drive redamon.sh over SSH, and wrap the whole thing in an
#  internet-facing security layer (nginx + TLS + firewall + host hardening) that
#  redamon.sh deliberately does NOT provide (RedAmon is designed local-only).
#
#  Public surface reduced to ONE PORT: 443. That serves the webapp UI and, when
#  MCP_SERVER_ENABLED=true, the credentialed inbound MCP endpoint
#  (/api/mcp-server) that external AI agents connect to. The agent
#  API, MCP servers, DBs, orchestrator and reverse-shell catcher stay on loopback.
#
#  Config lives in tooling/deploy/single-host/.env (see .env.example). A run is just:
#      ./deploy.sh init
#  CLI positionals override the .env connection fields.
#
#  MODES: init | update | status | harden | ssl-renew | down | logs
#  See ./deploy.sh help  and README.md.
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REMOTE_TMP="/tmp/redamon-deploy"

# ------------------------------------------------------------------ logging
c_reset=$'\e[0m'; c_bold=$'\e[1m'; c_red=$'\e[31m'; c_grn=$'\e[32m'; c_ylw=$'\e[33m'; c_blu=$'\e[34m'
log()  { echo "${c_blu}•${c_reset} $*"; }
ok()   { echo "${c_grn}✅${c_reset} $*"; }
warn() { echo "${c_ylw}⚠️ ${c_reset} $*" >&2; }
die()  { echo "${c_red}✖${c_reset} $*" >&2; exit 1; }
hr()   { echo "${c_bold}==== $* ====${c_reset}"; }

usage() {
  cat <<'USAGE'
Usage: ./deploy.sh <MODE> [HOST_IP] [AUTH] [REMOTE_USER] [--env ENV_NAME]

  MODE         init | update | status | harden | ssl-renew | down | logs
               | revshell-open | revshell-close                            (required)
  HOST_IP      Public IP or DNS of the target      (default: $HOST_IP from .env)
  AUTH         path/to/key.pem | pass | pass:<pw>   (default: $SSH_KEY_PATH / $SSH_PASSWORD)
  REMOTE_USER  ssh sudoer (ubuntu, admin, ...)      (default: $REMOTE_USER from .env)
  --env NAME   config selector -> tooling/deploy/single-host/.env.<NAME>  (default: .env)

Examples:
  ./deploy.sh init
  ./deploy.sh update
  ./deploy.sh init 1.2.3.4 ~/.ssh/redamon.pem ubuntu
  ./deploy.sh status --env staging
  ./deploy.sh logs agent
  ./deploy.sh revshell-open      # per-engagement: expose 4444 to REVSHELL_TARGET_CIDRS
  ./deploy.sh revshell-close     # tear the 4444 forwarder down
USAGE
  exit 1
}

# ------------------------------------------------------------------ arg parse
[[ $# -lt 1 ]] && usage
MODE="$1"; shift || true
[[ "${MODE}" =~ ^(init|update|status|harden|ssl-renew|down|logs|revshell-open|revshell-close)$ ]] || { warn "Unknown MODE: ${MODE}"; usage; }

ENV_NAME=""
CLI_HOST_IP=""; CLI_AUTH=""; CLI_REMOTE_USER=""; LOGS_SERVICE="agent"
POSITIONAL=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) [[ -n "${2:-}" ]] || { warn "--env needs a name"; usage; }; ENV_NAME="$2"; shift 2 ;;
    --env=*) ENV_NAME="${1#*=}"; shift ;;
    *) POSITIONAL+=("$1"); shift ;;
  esac
done
# For 'logs', the first positional is the service name; otherwise connection overrides.
if [[ "${MODE}" == "logs" ]]; then
  [[ ${#POSITIONAL[@]} -ge 1 ]] && LOGS_SERVICE="${POSITIONAL[0]}"
else
  CLI_HOST_IP="${POSITIONAL[0]:-}"
  CLI_AUTH="${POSITIONAL[1]:-}"
  CLI_REMOTE_USER="${POSITIONAL[2]:-}"
fi

# ------------------------------------------------------------------ load .env
ENV_FILE="${SCRIPT_DIR}/.env"
[[ -n "${ENV_NAME}" ]] && ENV_FILE="${SCRIPT_DIR}/.env.${ENV_NAME}"

# Pre-6.9 layout rescue: this directory used to live at <repo>/deploy/single-host.
# `git pull` moves only tracked files, so an operator upgrading across the
# reorganization keeps their (git-ignored) .env and TLS material at the old path
# while this script now runs from tooling/deploy/single-host. Adopt the legacy
# config instead of failing with a confusing "HOST_IP is empty".
LEGACY_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)/deploy/single-host"
if [[ ! -f "${ENV_FILE}" && -f "${LEGACY_DIR}/$(basename "${ENV_FILE}")" ]]; then
  warn "Found pre-6.9 deploy config at ${LEGACY_DIR}"
  warn "Run './redamon.sh migrate-layout' from the repo root to move it permanently."
  ENV_FILE="${LEGACY_DIR}/$(basename "${ENV_FILE}")"
  # TLS material is resolved relative to SCRIPT_DIR further down; point the
  # relative cert paths at the legacy directory for this run.
  [[ -d "${LEGACY_DIR}/cert" && ! -e "${SCRIPT_DIR}/cert/fullchain.pem" ]] && LEGACY_CERT_DIR="${LEGACY_DIR}"
fi

if [[ -f "${ENV_FILE}" ]]; then
  set -a; # shellcheck disable=SC1090
  source "${ENV_FILE}"; set +a
  log "Loaded config: $(basename "${ENV_FILE}")"
else
  warn "Config file ${ENV_FILE} not found -- relying on CLI positionals + env"
fi

# CLI positionals override .env connection fields
[[ -n "${CLI_HOST_IP}" ]]     && { HOST_IP="${CLI_HOST_IP}"; log "HOST_IP from CLI"; }
[[ -n "${CLI_REMOTE_USER}" ]] && { REMOTE_USER="${CLI_REMOTE_USER}"; log "REMOTE_USER from CLI"; }

# Defaults for optional keys (so `set -u` is safe throughout)
: "${REMOTE_USER:=ubuntu}"; : "${SSH_PORT:=22}"; : "${APP_DIR:=redamon}"
: "${REPO_URL:=https://github.com/samugit83/redamon.git}"; : "${REPO_BRANCH:=master}"
: "${ACCESS_MODE:=https-domain}"; : "${DOMAIN:=}"; : "${HTTP_PORT:=80}"; : "${HTTPS_PORT:=443}"
: "${TLS_MODE:=letsencrypt}"; : "${LETSENCRYPT_EMAIL:=}"; : "${LETSENCRYPT_STAGING:=false}"
: "${SSL_CERT_LOCAL:=cert/fullchain.pem}"; : "${SSL_KEY_LOCAL:=cert/privkey.pem}"; : "${SSL_KEY_PASSWORD:=}"
# Base dir for the relative SSL_*_LOCAL paths (see the pre-6.9 layout rescue above).
CERT_BASE="${LEGACY_CERT_DIR:-$SCRIPT_DIR}"
: "${HSTS_ENABLE:=true}"
: "${OPERATOR_ALLOW_CIDRS:=}"; : "${SSH_ALLOW_CIDRS:=}"; : "${GATE_MODE:=ip_allowlist}"
: "${BASIC_AUTH_USER:=}"; : "${BASIC_AUTH_PASS:=}"
: "${WS_REQUIRE_SESSION:=true}"; : "${CSP_ENFORCE:=false}"
: "${ENABLE_UFW:=true}"; : "${ENABLE_SSH_HARDENING:=true}"; : "${ENABLE_FAIL2BAN:=true}"; : "${ENABLE_UNATTENDED_UPGRADES:=true}"
: "${ENABLE_GVM:=false}"; : "${ENABLE_KB:=false}"; : "${ENABLE_KB_REFRESH:=false}"; : "${ENABLE_ZRAM:=true}"
: "${SWAP_PCT:=25}"; : "${SWAP_SIZE_GB:=}"; : "${REDAMON_SKIP_RAM_GATE:=false}"; : "${REDAMON_SKIP_DISK_GATE:=false}"; : "${REDAMON_BUILD_PARALLEL:=}"; : "${DOCKER_DNS:=}"; : "${DOCKER_BUILD_CACHE_MAX_GB:=}"
: "${REVSHELL_TARGET_CIDRS:=}"; : "${TUNNELS_ENABLED:=false}"
# Inbound MCP server (/api/mcp-server): an external AI agent connects IN with a
# bearer token and acts as one RedAmon user. OFF by default -- a credentialed
# programmatic surface must be switched on deliberately, never inherited by an
# upgrade. MCP_CLIENT_CIDRS is separate from OPERATOR_ALLOW_CIDRS because the
# firewall cannot filter by URL path: without it, ufw drops an agent's packet
# before nginx ever sees the exact-match location.
: "${MCP_SERVER_ENABLED:=false}"; : "${MCP_EDGE_ALLOW_BEARER:=false}"; : "${MCP_CLIENT_CIDRS:=}"
: "${MCP_TOKEN_RETENTION_DAYS:=}"; : "${MCP_LLM_DAILY_BUDGET:=}"; : "${MCP_RATE_MUTE_PER_MIN:=}"
: "${MCP_RATE_READ_PER_MIN:=}"; : "${MCP_RATE_QUERY_PER_MIN:=}"; : "${MCP_RATE_WRITE_PER_MIN:=}"
: "${MCP_RATE_START_PER_WINDOW:=}"; : "${MCP_RATE_START_WINDOW_MS:=}"
: "${MCP_RATE_COMPARE_PER_WINDOW:=}"; : "${MCP_RATE_COMPARE_WINDOW_MS:=}"
: "${MCP_KALI_EXEC_ENABLED:=true}"; : "${MCP_RATE_EXEC_PER_MIN:=}"
# Agent in the Loop rides on the MCP server: on by default, inert unless
# MCP_SERVER_ENABLED is on too (that one stays off by default on a deployed host).
: "${AGENT_IN_THE_LOOP_ENABLED:=true}"; : "${MCP_RATE_LOOP_PER_MIN:=}"
: "${MCP_DISABLED_TOOLS:=}"
: "${MCP_TOKEN_PRUNE_INTERVAL:=}"
: "${ADMIN_NAME:=}"; : "${ADMIN_EMAIL:=}"; : "${ADMIN_PASSWORD:=}"
: "${NVD_API_KEY:=}"; : "${KB_EMBEDDING_USE_API:=}"; : "${KB_EMBEDDING_API_BASE_URL:=}"; : "${KB_EMBEDDING_API_KEY:=}"
# Offline OSV database (supply-chain SCA). Blank -> the app's own defaults
# (refresh on, all 8 ecosystems, 24h TTL). Only an air-gapped host or a
# bandwidth/disk-constrained one needs to pin these; see README "Supply-chain".
: "${OSV_DB_AUTO_REFRESH:=}"; : "${OSV_DB_ECOSYSTEMS:=}"; : "${OSV_DB_TTL_SECONDS:=}"; : "${OSV_DB_REFRESH_TIMEOUT:=}"
: "${REDAMON_VERSION:=}"
: "${INIT_FORCE:=false}"; : "${BACKUP_BEFORE_UPDATE:=false}"; : "${DRY_RUN:=false}"; : "${VERBOSE:=false}"
: "${ALLOW_INSECURE:=0}"
: "${HOST_IP:=}"; : "${SSH_KEY_PATH:=}"; : "${SSH_PASSWORD:=}"

is_true() { [[ "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" == "true" || "${1:-}" == "1" ]]; }

# ------------------------------------------------------------------ derive ACCESS_MODE behaviour
case "${ACCESS_MODE}" in
  https-domain) PUBLIC_HOST="${DOMAIN}"; WS_SCHEME="wss"; HTTP_SCHEME="https"; SERVER_NAME="${DOMAIN}"; APPLY_SECURE_COOKIE=true ;;
  https-ip)     PUBLIC_HOST="${HOST_IP}"; WS_SCHEME="wss"; HTTP_SCHEME="https"; SERVER_NAME="_";        APPLY_SECURE_COOKIE=true ;;
  http-domain)  PUBLIC_HOST="${DOMAIN}"; WS_SCHEME="ws";  HTTP_SCHEME="http";  SERVER_NAME="${DOMAIN}"; APPLY_SECURE_COOKIE=false ;;
  http-ip)      PUBLIC_HOST="${HOST_IP}"; WS_SCHEME="ws";  HTTP_SCHEME="http";  SERVER_NAME="_";        APPLY_SECURE_COOKIE=false ;;
  *) die "Invalid ACCESS_MODE: ${ACCESS_MODE} (https-domain|https-ip|http-domain|http-ip)" ;;
esac
NEXT_PUBLIC_AGENT_WS_URL="${WS_SCHEME}://${PUBLIC_HOST}/ws/agent"
AGENT_CORS_ORIGINS="${HTTP_SCHEME}://${PUBLIC_HOST}"
# The origin a BROWSER would send, port included when non-default. nginx forwards
# `Host $host`, which drops the port, so the webapp cannot reconstruct this on a
# non-443/80 deploy and would reject a same-origin client as cross-origin.
if [[ "${HTTP_SCHEME}" == "https" && "${HTTPS_PORT}" != "443" ]]; then
  MCP_PUBLIC_ORIGIN="${HTTP_SCHEME}://${PUBLIC_HOST}:${HTTPS_PORT}"
elif [[ "${HTTP_SCHEME}" == "http" && "${HTTP_PORT}" != "80" ]]; then
  MCP_PUBLIC_ORIGIN="${HTTP_SCHEME}://${PUBLIC_HOST}:${HTTP_PORT}"
else
  MCP_PUBLIC_ORIGIN="${HTTP_SCHEME}://${PUBLIC_HOST}"
fi
CSP_CONNECT="${WS_SCHEME}://${PUBLIC_HOST}"
WEBAPP_NODE_ENV="production"
NEED_CERTBOT=false; [[ "${TLS_MODE}" == "letsencrypt" ]] && NEED_CERTBOT=true

# ------------------------------------------------------------------ local preflight validation
preflight_validate() {
  hr "Local preflight"
  [[ -n "${HOST_IP}" ]] || die "HOST_IP is empty (set it in .env or pass as CLI positional)"

  case "${ACCESS_MODE}" in
    *-domain) [[ -n "${DOMAIN}" ]] || die "ACCESS_MODE=${ACCESS_MODE} requires DOMAIN" ;;
    *-ip)     [[ "${HOST_IP}" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "ACCESS_MODE=${ACCESS_MODE} requires HOST_IP to be an IP literal" ;;
  esac

  if is_true "${NEED_CERTBOT}"; then
    [[ "${ACCESS_MODE}" == "https-domain" ]] || die "TLS_MODE=letsencrypt requires ACCESS_MODE=https-domain (LE cannot issue for a bare IP)"
    [[ -n "${LETSENCRYPT_EMAIL}" ]] || die "TLS_MODE=letsencrypt requires LETSENCRYPT_EMAIL"
    [[ "${HTTP_PORT}" == "80" ]] || die "TLS_MODE=letsencrypt requires HTTP_PORT=80 (the ACME http-01 challenge always validates on port 80)"
  fi
  if [[ "${ACCESS_MODE}" == https-* ]]; then
    case "${TLS_MODE}" in
      letsencrypt|provided|self-signed) : ;;
      *) die "Invalid TLS_MODE '${TLS_MODE}' for ${ACCESS_MODE}" ;;
    esac
    [[ "${ACCESS_MODE}" == "https-domain" && "${TLS_MODE}" == "self-signed" ]] && die "self-signed is for https-ip; use letsencrypt/provided for a domain"
    if [[ "${TLS_MODE}" == "provided" ]]; then
      [[ -f "${CERT_BASE}/${SSL_CERT_LOCAL}" ]] || die "TLS_MODE=provided: cert not found at ${CERT_BASE}/${SSL_CERT_LOCAL}"
      [[ -f "${CERT_BASE}/${SSL_KEY_LOCAL}"  ]] || die "TLS_MODE=provided: key not found at ${CERT_BASE}/${SSL_KEY_LOCAL}"
    fi
  fi

  if [[ "${ACCESS_MODE}" == http-* ]]; then
    warn "${c_bold}INSECURE MODE (${ACCESS_MODE})${c_reset}: plaintext cookies/creds over the wire, no HSTS, agent WS unencrypted."
    warn "This inverts the single-origin security posture. Lab/test ONLY."
    is_true "${ALLOW_INSECURE}" || die "Refusing http-* mode without ALLOW_INSECURE=1 (set it in .env or the environment)"
  fi

  if [[ "${GATE_MODE}" == "basic_auth" ]]; then
    [[ -n "${BASIC_AUTH_USER}" && -n "${BASIC_AUTH_PASS}" ]] || die "GATE_MODE=basic_auth requires BASIC_AUTH_USER/BASIC_AUTH_PASS"
  fi

  if is_true "${MCP_SERVER_ENABLED}"; then
    # REFUSED, not warned: the whole credential is a bearer token in a header.
    # Over http-* it crosses the wire in plaintext on every single call, and the
    # token outlives the session, so one capture is a durable credential.
    # ALLOW_INSECURE covers "my cookies are plaintext"; it does not cover
    # "I am broadcasting a long-lived API credential".
    [[ "${ACCESS_MODE}" == http-* ]] && die "MCP_SERVER_ENABLED=true is refused in ${ACCESS_MODE}: a bearer token would travel in plaintext on every call. Use an https-* ACCESS_MODE."

    if [[ "${GATE_MODE}" == "basic_auth" ]] && ! is_true "${MCP_EDGE_ALLOW_BEARER}"; then
      warn "MCP is enabled but GATE_MODE=basic_auth consumes the Authorization header: /api/mcp-server will return 403. Set MCP_EDGE_ALLOW_BEARER=true to open it."
    fi
    # The firewall gates the port before nginx ever sees the path, so an agent
    # outside both CIDR lists is dropped no matter what the location says.
    if [[ -n "${OPERATOR_ALLOW_CIDRS}" && -z "${MCP_CLIENT_CIDRS}" ]]; then
      warn "MCP is enabled and the firewall scopes the app port to OPERATOR_ALLOW_CIDRS. An agent outside those CIDRs is blocked BEFORE nginx. Set MCP_CLIENT_CIDRS to admit it."
    fi
    if [[ "${ACCESS_MODE}" == "https-ip" && "${TLS_MODE}" != "provided" ]]; then
      warn "MCP over https-ip with a self-signed cert: most MCP clients reject the certificate. Use a real cert (TLS_MODE=provided) or a domain."
    fi
  fi
  # A note, not a warning: the loop switch is on by default and harmless while
  # the server is off, which is this deploy's default.
  if is_true "${AGENT_IN_THE_LOOP_ENABLED}" && ! is_true "${MCP_SERVER_ENABLED}"; then
    log "AGENT_IN_THE_LOOP_ENABLED=true but MCP_SERVER_ENABLED is off: an external agent reaches its steps over the MCP server, so Agent in the Loop stays inert until you turn the MCP server on."
  fi
  [[ -z "${OPERATOR_ALLOW_CIDRS}" && "${GATE_MODE}" == "ip_allowlist" ]] && warn "GATE_MODE=ip_allowlist but OPERATOR_ALLOW_CIDRS is empty -> the nginx gate will allow all"

  if [[ "${MODE}" == "init" ]]; then
    [[ -n "${ADMIN_NAME}" && -n "${ADMIN_EMAIL}" && -n "${ADMIN_PASSWORD}" ]] \
      || die "init requires ADMIN_NAME, ADMIN_EMAIL and ADMIN_PASSWORD in .env (the first admin is created automatically)"
    [[ ${#ADMIN_PASSWORD} -ge 8 ]] || warn "ADMIN_PASSWORD is short; there is no app-layer login lockout (nginx limit_req is the only brake)"
  fi
  ok "Preflight passed (ACCESS_MODE=${ACCESS_MODE}, TLS_MODE=${TLS_MODE}, host=${HOST_IP}, user=${REMOTE_USER})"
}

# ------------------------------------------------------------------ SSH/SCP abstraction
AUTH_MODE=""; PEM=""; SUDO_PASS=""
setup_ssh() {
  local auth="${CLI_AUTH}"
  # Resolve AUTH: CLI positional > SSH_KEY_PATH > SSH_PASSWORD
  if [[ -z "${auth}" ]]; then
    if [[ -n "${SSH_KEY_PATH}" ]]; then auth="${SSH_KEY_PATH/#\~/$HOME}"
    elif [[ -n "${SSH_PASSWORD}" ]]; then auth="pass:${SSH_PASSWORD}"
    else die "No SSH auth: set SSH_KEY_PATH or SSH_PASSWORD in .env, or pass AUTH on the CLI"; fi
  fi
  auth="${auth/#\~/$HOME}"

  if [[ -f "${auth}" ]]; then
    AUTH_MODE="key"; PEM="${auth}"
  elif [[ "${auth}" == "pass" || "${auth}" == "-" ]]; then
    AUTH_MODE="password"; read -ers -p "SSH password for ${REMOTE_USER}@${HOST_IP}: " SSH_PASSWORD; echo
  elif [[ "${auth}" == pass:* ]]; then
    AUTH_MODE="password"; SSH_PASSWORD="${auth#pass:}"
  else
    AUTH_MODE="password"; SSH_PASSWORD="${auth}"
  fi

  if [[ "${AUTH_MODE}" == "password" ]]; then
    command -v sshpass >/dev/null 2>&1 || die "password auth needs 'sshpass' locally (apt install sshpass / brew install hudochenkov/sshpass/sshpass)"
    export SSHPASS="${SSH_PASSWORD}"
    SUDO_PASS="${SSH_PASSWORD}"
  fi

# ---------------------------------------------------------------------------
# Refuse an undersized target BEFORE provisioning anything.
#
# Without this the deploy installs Docker + nginx, clones the repo and drives
# redamon.sh install -- 30-60 minutes of work -- only for the host to be too
# small for the stack it just built. redamon.sh gates too, but by then the box
# has already been mutated. Checking over SSH costs one round trip.
#
# The requirement tracks the ENABLED PROFILES, because GVM roughly doubles it.
# Override with REDAMON_SKIP_RAM_GATE / REDAMON_SKIP_DISK_GATE, exactly as on the
# host itself.
# ---------------------------------------------------------------------------
precheck_target() {
  local need_gb=8 need_disk=40 why="core services"
  if is_true "${ENABLE_GVM}"; then need_gb=16; need_disk=60; why="core + GVM"; fi
  if is_true "${ENABLE_KB}";  then need_gb=$(( need_gb + 4 )); need_disk=$(( need_disk + 20 )); why="$why + KB"; fi

  local probe mem_gb disk_gb
  probe="$($SSH "awk '/MemTotal/{printf \"%d\", \$2/1024/1024}' /proc/meminfo; echo ' '; df -BG --output=avail / 2>/dev/null | tail -1 | tr -dc '0-9'" 2>/dev/null)" || true
  mem_gb="${probe%% *}"; disk_gb="${probe##* }"

  if [[ ! "$mem_gb" =~ ^[0-9]+$ || ! "$disk_gb" =~ ^[0-9]+$ ]]; then
    warn "Could not read the target's RAM/disk; skipping the precheck (redamon.sh will still gate)."
    return 0
  fi
  log "Target: ~${mem_gb}GB RAM, ${disk_gb}GB free disk (need ~${need_gb}GB / ~${need_disk}GB for ${why})"

  if [[ "$mem_gb" -lt "$need_gb" ]] && ! is_true "${REDAMON_SKIP_RAM_GATE}"; then
    err "Target has ~${mem_gb}GB RAM; ${why} needs ~${need_gb}GB."
    err "  Use a bigger instance, disable a profile (ENABLE_GVM/ENABLE_KB=false),"
    err "  or set REDAMON_SKIP_RAM_GATE=true to proceed anyway (expect OOM kills)."
    die "Aborted before touching the host."
  fi
  if [[ "$disk_gb" -lt "$need_disk" ]] && ! is_true "${REDAMON_SKIP_DISK_GATE}"; then
    err "Target has ${disk_gb}GB free; the ${why} build needs ~${need_disk}GB."
    err "  Grow the volume, or set REDAMON_SKIP_DISK_GATE=true (the build may fail part-way)."
    die "Aborted before touching the host."
  fi
  ok "Target sizing OK"
}

  SSH_CONTROL_PATH="/tmp/ssh-redamon-${HOST_IP}-$$"
  local common="-p ${SSH_PORT} -o StrictHostKeyChecking=accept-new -o ServerAliveInterval=30 -o ServerAliveCountMax=8 -o ControlMaster=auto -o ControlPath=${SSH_CONTROL_PATH} -o ControlPersist=120"
  local scp_common="-P ${SSH_PORT} -o StrictHostKeyChecking=accept-new -o ControlMaster=auto -o ControlPath=${SSH_CONTROL_PATH} -o ControlPersist=120"
  if [[ "${AUTH_MODE}" == "key" ]]; then
    SSH="ssh ${common} -i ${PEM} ${REMOTE_USER}@${HOST_IP}"
    SCP="scp -q ${scp_common} -i ${PEM}"
  else
    SSH="sshpass -e ssh -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no ${common} ${REMOTE_USER}@${HOST_IP}"
    SCP="sshpass -e scp -o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -q ${scp_common}"
  fi
  trap cleanup_ssh EXIT
  log "Establishing SSH to ${REMOTE_USER}@${HOST_IP}:${SSH_PORT} ..."
  $SSH "echo ok" >/dev/null || die "SSH connection failed"
  ok "SSH connected"
  precheck_target
}
cleanup_ssh() {
  # I7: remove the transient remote secrets (deploy.env carries AUTH_SECRET, all
  # API keys, NEO4J_PASSWORD, ADMIN_PASSWORD, and in password mode SUDO_PASSWORD;
  # cert/ holds provided TLS keys) as soon as the run exits — including on error
  # or abort — instead of leaving them in /tmp until the NEXT run. shred first
  # where available (defense-in-depth), then rm -rf the whole staging dir.
  if [[ -n "${SSH:-}" ]]; then
    $SSH "shred -u ${REMOTE_TMP}/deploy.env 2>/dev/null; rm -rf ${REMOTE_TMP}/deploy.env ${REMOTE_TMP}/cert ${REMOTE_TMP}" 2>/dev/null || true
  fi
  # Remove the local staged copy too.
  rm -f "${SCRIPT_DIR}/.deploy.env.staged" 2>/dev/null || true
  [[ -S "${SSH_CONTROL_PATH:-}" ]] && ssh -o ControlPath="${SSH_CONTROL_PATH}" -O exit "${REMOTE_USER}@${HOST_IP}" 2>/dev/null || true
}

# Run a bash snippet remotely. Usage: remote <<EOF ... EOF  (the heredoc starts with
# ${PREAMBLE}, which sources modules/_common.sh + deploy.env; docker via `sg docker -c`).
# SUDO_PASSWORD (password mode only) reaches run_sudo via the %q-quoted deploy.env, NOT via
# the command line -- so passwords with quotes/spaces are safe and never hit argv/ps.
remote() {
  $SSH "bash -s"
}

# ------------------------------------------------------------------ build + ship deploy.env
build_deploy_env() {
  local f="${SCRIPT_DIR}/.deploy.env.staged"
  {
    echo "# generated by deploy.sh -- do not edit; transient, chmod 600, shred+rm'd on run exit (cleanup_ssh EXIT trap; I7)"
    for k in APP_DIR REPO_URL REPO_BRANCH REMOTE_USER HOST_IP SSH_PORT \
             ACCESS_MODE DOMAIN HTTP_PORT HTTPS_PORT SERVER_NAME PUBLIC_HOST \
             TLS_MODE LETSENCRYPT_EMAIL LETSENCRYPT_STAGING SSL_KEY_PASSWORD HSTS_ENABLE NEED_CERTBOT \
             OPERATOR_ALLOW_CIDRS SSH_ALLOW_CIDRS GATE_MODE BASIC_AUTH_USER BASIC_AUTH_PASS \
             WS_REQUIRE_SESSION CSP_ENFORCE \
             ENABLE_UFW ENABLE_SSH_HARDENING ENABLE_FAIL2BAN ENABLE_UNATTENDED_UPGRADES \
             ENABLE_GVM ENABLE_KB ENABLE_KB_REFRESH ENABLE_ZRAM \
             SWAP_SIZE_GB SWAP_PCT REDAMON_SKIP_RAM_GATE REDAMON_SKIP_DISK_GATE REDAMON_BUILD_PARALLEL DOCKER_DNS DOCKER_BUILD_CACHE_MAX_GB \
             OS_RESERVE_PCT SERVICES_PCT BURST_FACTOR BURST_SWAP_MIN_PCT BLAST_PCT DISK_RESERVE_PCT \
             REDAMON_WEIGHT_WEBAPP REDAMON_WEIGHT_NEO4J REDAMON_WEIGHT_AGENT \
             REVSHELL_TARGET_CIDRS TUNNELS_ENABLED \
             MCP_SERVER_ENABLED MCP_EDGE_ALLOW_BEARER MCP_CLIENT_CIDRS \
             MCP_TOKEN_RETENTION_DAYS MCP_LLM_DAILY_BUDGET MCP_RATE_MUTE_PER_MIN \
             MCP_RATE_READ_PER_MIN MCP_RATE_QUERY_PER_MIN MCP_RATE_WRITE_PER_MIN \
             MCP_RATE_START_PER_WINDOW MCP_RATE_START_WINDOW_MS MCP_TOKEN_PRUNE_INTERVAL \
             MCP_RATE_COMPARE_PER_WINDOW MCP_RATE_COMPARE_WINDOW_MS \
             MCP_KALI_EXEC_ENABLED MCP_RATE_EXEC_PER_MIN \
             AGENT_IN_THE_LOOP_ENABLED MCP_RATE_LOOP_PER_MIN \
             MCP_DISABLED_TOOLS \
             MCP_PUBLIC_ORIGIN \
             ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD \
             NVD_API_KEY KB_EMBEDDING_USE_API KB_EMBEDDING_API_BASE_URL KB_EMBEDDING_API_KEY \
             OSV_DB_AUTO_REFRESH OSV_DB_ECOSYSTEMS OSV_DB_TTL_SECONDS OSV_DB_REFRESH_TIMEOUT \
             SCA_INTEL_AUTO_REFRESH SCA_INTEL_TTL_SECONDS SCA_INTEL_RETRY_SECONDS \
             SCA_INTEL_REFRESH_TIMEOUT SCA_INTEL_BOOTSTRAP_ON_SCAN SCA_INTEL_MATCH_ENABLED \
             CAPTURE_IOC_IGNORE_SUFFIXES \
             REDAMON_VERSION AUTH_MODE APPLY_SECURE_COOKIE \
             NEXT_PUBLIC_AGENT_WS_URL AGENT_CORS_ORIGINS CSP_CONNECT WEBAPP_NODE_ENV WS_SCHEME HTTP_SCHEME; do
      printf '%s=%q\n' "$k" "${!k:-}"
    done
    # Password mode only: run_sudo needs the sudo password. Written here (%q-quoted, 600,
    # rm'd on cleanup) so it never appears on a remote command line / in ps. Key mode
    # assumes passwordless sudo, so nothing is written.
    [[ "${AUTH_MODE}" == "password" ]] && printf 'SUDO_PASSWORD=%q\n' "${SUDO_PASS}"
  } > "$f"
  chmod 600 "$f"
  echo "$f"
}

ship_assets() {
  hr "Ship deploy assets -> ${HOST_IP}:${REMOTE_TMP}"
  $SSH "rm -rf ${REMOTE_TMP} && mkdir -p ${REMOTE_TMP}"
  $SCP -r "${SCRIPT_DIR}/modules" "${SCRIPT_DIR}/nginx" "${SCRIPT_DIR}/compose" "${REMOTE_USER}@${HOST_IP}:${REMOTE_TMP}/"
  # provided-TLS material
  if [[ "${TLS_MODE}" == "provided" ]]; then
    $SSH "mkdir -p ${REMOTE_TMP}/cert"
    $SCP "${CERT_BASE}/${SSL_CERT_LOCAL}" "${REMOTE_USER}@${HOST_IP}:${REMOTE_TMP}/cert/fullchain.pem"
    $SCP "${CERT_BASE}/${SSL_KEY_LOCAL}"  "${REMOTE_USER}@${HOST_IP}:${REMOTE_TMP}/cert/privkey.pem"
    $SSH "chmod 600 ${REMOTE_TMP}/cert/*"
  fi
  local envf; envf="$(build_deploy_env)"
  $SCP "${envf}" "${REMOTE_USER}@${HOST_IP}:${REMOTE_TMP}/deploy.env"
  $SSH "chmod 600 ${REMOTE_TMP}/deploy.env"
  rm -f "${envf}"
  ok "Assets shipped"
}

# common remote preamble (sourced at the top of every remote heredoc).
# The prod overlay lives at a PERSISTENT ABSOLUTE path OUTSIDE the repo tree
# ($HOME/.redamon-deploy) so it (a) survives reboots, (b) never dirties the git checkout
# (so redamon.sh update's `git pull --ff-only` can't be blocked by it), and (c) does not
# depend on the deploy dir being committed to the cloned branch. docker compose resolves
# the relative base file from CWD ($APP_PATH) and the absolute overlay from its full path.
PREAMBLE='set -euo pipefail
cd '"${REMOTE_TMP}"'
source modules/_common.sh
set -a; source deploy.env; set +a
APP_PATH="$HOME/${APP_DIR}"
OVERLAY_DIR="$HOME/.redamon-deploy"
mkdir -p "$OVERLAY_DIR"
cp -f '"${REMOTE_TMP}"'/compose/docker-compose.prod.yml "$OVERLAY_DIR/docker-compose.prod.yml" 2>/dev/null || true
export COMPOSE_FILE="docker-compose.yml:$OVERLAY_DIR/docker-compose.prod.yml"'

# ============================================================================
#  MODE: init
# ============================================================================
cmd_init() {
  hr "INIT ${HOST_IP}  (DESTRUCTIVE -- wipes ALL Docker state + the checkout)"
  if ! is_true "${INIT_FORCE}"; then
    echo "This ERASES every container, image, volume and network on ${HOST_IP} (not just RedAmon)."
    read -erp "Type INIT to wipe ${HOST_IP}: " confirm
    [[ "${confirm}" == "INIT" ]] || die "Aborted (confirmation not given)"
  fi
  ship_assets

  hr "Host teardown"
  remote <<EOF
${PREAMBLE}
step "Teardown: graceful RedAmon purge + full docker prune + remove checkout"
if [ -x "\$APP_PATH/redamon.sh" ]; then
  ( cd "\$APP_PATH" && sg docker -c "./redamon.sh purge" <<<"yes" ) || true
fi
sg docker -c 'docker ps -aq | xargs -r docker rm -f' || true
sg docker -c 'docker system prune -af --volumes' || true
sg docker -c 'docker network prune -f' || true
# Use sudo: containers create root-owned files in bind-mounted repo subdirs
# (recon_orchestrator/__pycache__, agentic/logs/agent.log, ...), which an unprivileged
# rm cannot delete. Without sudo the checkout is left half-removed and the later
# git clone fails ("destination path already exists and is not an empty directory"),
# aborting every RE-init (a first init works only because the path does not exist yet).
run_sudo rm -rf "\$APP_PATH"
success "Teardown complete"
EOF

  hr "Host bootstrap (detect + install prerequisites)"
  remote <<EOF
${PREAMBLE}
source modules/host_bootstrap.sh
host_bootstrap
EOF

  hr "Host hardening"
  remote <<EOF
${PREAMBLE}
source modules/ssh_hardening.sh
source modules/firewall.sh
source modules/fail2ban.sh
source modules/unattended_upgrades.sh
setup_ssh_hardening
setup_firewall
setup_fail2ban
setup_unattended_upgrades
EOF

  hr "Clone repo + install overlay + seed app .env"
  remote <<EOF
${PREAMBLE}
step "Clone ${REPO_URL} (${REPO_BRANCH}) -> \$APP_PATH"
git clone -b "\${REPO_BRANCH}" --depth 1 "\${REPO_URL}" "\$APP_PATH"
cd "\$APP_PATH"
# (the prod overlay is installed at \$OVERLAY_DIR by PREAMBLE, outside the repo tree)
# No deploy-time source patches: the single-origin agent WebSocket URL is now a
# first-class build ARG in the base webapp/Dockerfile (NEXT_PUBLIC_AGENT_WS_URL),
# baked from the prod overlay's build-arg. There is nothing to patch or reset, so a
# rebuild can never silently ship the wrong (localhost:8090) WS URL.
step "Seed application .env (operator app-config only; secrets are redamon.sh's job)"
touch .env
# A key is appended on a line of its own even when the operator's .env has no final newline.
seed() { local k="\$1" v="\$2"; [ -z "\$v" ] && return 0; grep -q "^\$k=" .env && sed -i "s|^\$k=.*|\$k=\$v|" .env || { [ -z "\$(tail -c1 .env)" ] || echo >> .env; echo "\$k=\$v" >> .env; }; }
seed NVD_API_KEY "\${NVD_API_KEY}"
seed KB_EMBEDDING_USE_API "\${KB_EMBEDDING_USE_API}"
seed KB_EMBEDDING_API_BASE_URL "\${KB_EMBEDDING_API_BASE_URL}"
seed KB_EMBEDDING_API_KEY "\${KB_EMBEDDING_API_KEY}"
seed TUNNELS_ENABLED "\${TUNNELS_ENABLED}"
# Offline OSV database (supply-chain SCA). redamon.sh install/update/up call
# ensure_osv_db, which downloads ~280 MB for all 8 ecosystems on a cold host.
# These are read by recon-orchestrator (explicitly wired in its compose
# environment block -- it has no env_file) and by redamon.sh's own sync step.
# Seed BEFORE the install so the very first sync already honours them: an
# air-gapped host must not spend 15 minutes on a download that cannot succeed.
seed OSV_DB_AUTO_REFRESH "\${OSV_DB_AUTO_REFRESH}"
seed OSV_DB_ECOSYSTEMS "\${OSV_DB_ECOSYSTEMS}"
seed OSV_DB_TTL_SECONDS "\${OSV_DB_TTL_SECONDS}"
seed OSV_DB_REFRESH_TIMEOUT "\${OSV_DB_REFRESH_TIMEOUT}"
# Supply-chain incident catalog. Same reason to seed BEFORE the install: an
# air-gapped host must be able to turn the fetch off before anything tries it.
seed SCA_INTEL_AUTO_REFRESH "\${SCA_INTEL_AUTO_REFRESH}"
seed SCA_INTEL_TTL_SECONDS "\${SCA_INTEL_TTL_SECONDS}"
seed SCA_INTEL_RETRY_SECONDS "\${SCA_INTEL_RETRY_SECONDS}"
seed SCA_INTEL_REFRESH_TIMEOUT "\${SCA_INTEL_REFRESH_TIMEOUT}"
seed SCA_INTEL_BOOTSTRAP_ON_SCAN "\${SCA_INTEL_BOOTSTRAP_ON_SCAN}"
seed SCA_INTEL_MATCH_ENABLED "\${SCA_INTEL_MATCH_ENABLED}"
seed CAPTURE_IOC_IGNORE_SUFFIXES "\${CAPTURE_IOC_IGNORE_SUFFIXES}"
# Inbound MCP server. Seeded BEFORE redamon.sh runs: ensure_auth_secrets appends
# MCP_SERVER_ENABLED=false when the key is ABSENT, so without this the deployed
# host actively pins the flag off and the operator's choice is unreachable.
# seed() overwrites an existing key, so re-running is idempotent either way.
seed MCP_SERVER_ENABLED "\${MCP_SERVER_ENABLED}"
# Marks this .env as a deployed server: redamon.sh then never turns its MCP server on.
seed REDAMON_SINGLE_HOST_DEPLOY true
seed MCP_TOKEN_RETENTION_DAYS "\${MCP_TOKEN_RETENTION_DAYS}"
seed MCP_LLM_DAILY_BUDGET "\${MCP_LLM_DAILY_BUDGET}"
seed MCP_RATE_MUTE_PER_MIN "\${MCP_RATE_MUTE_PER_MIN}"
seed MCP_RATE_READ_PER_MIN "\${MCP_RATE_READ_PER_MIN}"
seed MCP_RATE_QUERY_PER_MIN "\${MCP_RATE_QUERY_PER_MIN}"
seed MCP_RATE_WRITE_PER_MIN "\${MCP_RATE_WRITE_PER_MIN}"
seed MCP_RATE_START_PER_WINDOW "\${MCP_RATE_START_PER_WINDOW}"
seed MCP_RATE_START_WINDOW_MS "\${MCP_RATE_START_WINDOW_MS}"
seed MCP_RATE_COMPARE_PER_WINDOW "\${MCP_RATE_COMPARE_PER_WINDOW}"
seed MCP_RATE_COMPARE_WINDOW_MS "\${MCP_RATE_COMPARE_WINDOW_MS}"
seed MCP_KALI_EXEC_ENABLED "\${MCP_KALI_EXEC_ENABLED}"
seed MCP_RATE_EXEC_PER_MIN "\${MCP_RATE_EXEC_PER_MIN}"
seed AGENT_IN_THE_LOOP_ENABLED "\${AGENT_IN_THE_LOOP_ENABLED}"
seed MCP_RATE_LOOP_PER_MIN "\${MCP_RATE_LOOP_PER_MIN}"
seed MCP_DISABLED_TOOLS "\${MCP_DISABLED_TOOLS}"
seed MCP_TOKEN_PRUNE_INTERVAL "\${MCP_TOKEN_PRUNE_INTERVAL}"
# The webapp validates the request Origin against its own URL, which nginx
# builds from \`proxy_set_header Host \$host\` -- and \$host DROPS THE PORT. On a
# non-default HTTPS_PORT an Origin-sending client would be 403'd against its own
# origin, so the public origin is passed explicitly.
seed MCP_ALLOWED_ORIGIN "\${MCP_PUBLIC_ORIGIN}"
# The plugin routes check the request Origin like the MCP route, hence the same
# derived origin.
seed PLUGINS_ALLOWED_ORIGIN "\${MCP_PUBLIC_ORIGIN}"
# Behind nginx every request arrives from 127.0.0.1 unless the app is told the
# edge is trusted. nginx pins X-Forwarded-For to the real peer, so this is safe
# here and is what makes audit records and the login lockout name a real IP.
seed TRUST_PROXY "true"

# Memory-governor SHARES. Percentages only: redamon.sh computes the actual sizes
# from the remote host's own RAM, so the same values are correct on an 8GB and a
# 64GB instance. Seeding a size here would defeat the whole point.
seed OS_RESERVE_PCT "\${OS_RESERVE_PCT}"
seed SERVICES_PCT "\${SERVICES_PCT}"
seed BURST_FACTOR "\${BURST_FACTOR}"
seed BURST_SWAP_MIN_PCT "\${BURST_SWAP_MIN_PCT}"
seed BLAST_PCT "\${BLAST_PCT}"
seed DISK_RESERVE_PCT "\${DISK_RESERVE_PCT}"
seed REDAMON_WEIGHT_WEBAPP "\${REDAMON_WEIGHT_WEBAPP}"
seed REDAMON_WEIGHT_NEO4J "\${REDAMON_WEIGHT_NEO4J}"
seed REDAMON_WEIGHT_AGENT "\${REDAMON_WEIGHT_AGENT}"

# Cap each per-service CPU limit to the host's CPU count. compose sets generous
# \`cpus:\` defaults (neo4j 8, kali 10, agent 8) that assume a big host; Docker
# REFUSES to create a container whose cpus limit exceeds the host's CPU count, so
# on a 4-vCPU box \`up\` dies with "range of CPUs is from 0.01 to N.00". Seed
# min(default, nproc) so it auto-fits any instance; skip any value the operator
# already pinned in .env. \`cpus:\` is a limit not a reservation, so capping to
# nproc loses nothing (nproc was already the physical ceiling).
NPROC=\$(nproc 2>/dev/null || echo 1)
cap_cpus() {  # key generous_default
  local k="\$1" d="\$2"
  local v="\$d"                               # separate stmt: \$d isn't set within its own 'local'
  grep -q "^\$k=" .env && return 0            # respect an operator override
  [ "\$d" -gt "\$NPROC" ] && v="\$NPROC"
  seed "\$k" "\$v"
}
cap_cpus POSTGRES_CPUS 4
cap_cpus NEO4J_CPUS 8
cap_cpus KALI_CPUS 10
cap_cpus RECON_ORCHESTRATOR_CPUS 4
cap_cpus AGENT_CPUS 8
cap_cpus WEBAPP_CPUS 4
cap_cpus DOCKER_BROKER_CPUS 2
cap_cpus PLUGIN_RUNNER_CPUS 2
chmod 600 .env
success "Checkout ready"
EOF

  hr "Drive redamon.sh install (builds all images, brings the stack up)  [30-60 min]"
  drive_install
  run_secrets_gate
  bootstrap_admin
  setup_nginx_tls
  kb_refresh_start
  gvm_note
  verify

  echo
  ok "INIT complete."
  local url; url="${HTTP_SCHEME}://${PUBLIC_HOST}/"
  echo "   Login:  ${c_bold}${url}${c_reset}"
  echo "   Admin:  ${ADMIN_EMAIL}"
}

# redamon.sh install driven through a pty (expect) so its interactive admin prompt is
# answered non-interactively from ADMIN_* in .env -- the first admin is created at init.
drive_install() {
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH"
export DOMAIN NEXT_PUBLIC_AGENT_WS_URL AGENT_CORS_ORIGINS WEBAPP_NODE_ENV
[ -n "\${REDAMON_VERSION}" ] && export REDAMON_VERSION
is_true "\${ENABLE_ZRAM}" && export REDAMON_ENABLE_ZRAM=1
[ -n "\${REDAMON_BUILD_PARALLEL}" ] && export REDAMON_BUILD_PARALLEL
is_true "\${REDAMON_SKIP_RAM_GATE}" && export REDAMON_SKIP_RAM_GATE=1
INSTALL_FLAGS=""
is_true "\${ENABLE_GVM}" && INSTALL_FLAGS="\$INSTALL_FLAGS --gvm"
is_true "\${ENABLE_KB}"  && INSTALL_FLAGS="\$INSTALL_FLAGS --kbase"
export INSTALL_FLAGS APP_PATH ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD
cat > "${REMOTE_TMP}/drive_install.exp" <<'EXP'
#!/usr/bin/expect -f
set timeout -1
spawn bash -c "cd \$env(APP_PATH) && ./redamon.sh install \$env(INSTALL_FLAGS)"
expect {
  -re {Admin name:}                 { send "\$env(ADMIN_NAME)\r";     exp_continue }
  -re {Admin email:}                { send "\$env(ADMIN_EMAIL)\r";    exp_continue }
  -re {Confirm password:}           { send "\$env(ADMIN_PASSWORD)\r"; exp_continue }
  -re {Admin password:}             { send "\$env(ADMIN_PASSWORD)\r"; exp_continue }
  -re {Run full ingestion now.*\[y/N\]} { send "n\r";                exp_continue }
  eof
}
catch wait result
exit [lindex \$result 3]
EXP
step "redamon.sh install (pty-driven; admin auto-answered from .env)"
sg docker -c "expect ${REMOTE_TMP}/drive_install.exp"
success "redamon.sh install finished"
EOF
}

run_secrets_gate() {
  hr "Secrets gate"
  remote <<EOF
${PREAMBLE}
source modules/secrets_gate.sh
secrets_gate "\$APP_PATH/.env"
EOF
}

# idempotent guarantee: upsert the admin from .env (create-admin.mjs). No-op if the
# pty-driven install already made it. Needs the webapp container running (post-install).
bootstrap_admin() {
  hr "Admin bootstrap (idempotent guarantee)"
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH"
# Pass ADMIN_* by exported env (no inline interpolation) so names/passwords with
# spaces or shell-special chars are safe. 'docker compose exec -e KEY' (no =value)
# forwards the current environment value into the container.
export ADMIN_NAME ADMIN_EMAIL ADMIN_PASSWORD
if sg docker -c "cd \$APP_PATH && docker compose exec -T -e ADMIN_NAME -e ADMIN_EMAIL -e ADMIN_PASSWORD webapp node scripts/create-admin.mjs"; then
  success "Admin ensured: \${ADMIN_EMAIL}"
else
  warn "create-admin.mjs returned non-zero (admin may already exist)"
fi
EOF
}

# ============================================================================
#  nginx + TLS (shared by init and harden)
# ============================================================================
setup_nginx_tls() {
  hr "nginx + TLS (${ACCESS_MODE} / ${TLS_MODE})"
  remote <<EOF
${PREAMBLE}
source modules/nginx.sh
source modules/tls.sh
export SERVER_NAME CSP_CONNECT ACCESS_MODE TLS_MODE GATE_MODE OPERATOR_ALLOW_CIDRS BASIC_AUTH_USER BASIC_AUTH_PASS HSTS_ENABLE DOMAIN HOST_IP LETSENCRYPT_EMAIL LETSENCRYPT_STAGING SSL_KEY_PASSWORD WS_REQUIRE_SESSION CSP_ENFORCE HTTP_PORT HTTPS_PORT MCP_SERVER_ENABLED MCP_EDGE_ALLOW_BEARER MCP_CLIENT_CIDRS
case "\${ACCESS_MODE}" in
  https-*)
    if [ "\${TLS_MODE}" = "letsencrypt" ]; then
      if run_sudo test -f "/etc/letsencrypt/live/\${DOMAIN}/fullchain.pem"; then
        # Cert already issued (re-run of init/harden/update): render the real site
        # directly. Skipping the port-80 bootstrap avoids an HTTPS-down window.
        info "LE cert already present -- rendering hardened site directly (no ACME bootstrap)"
        SSL_CERT_REMOTE="/etc/letsencrypt/live/\${DOMAIN}/fullchain.pem"
        SSL_KEY_REMOTE="/etc/letsencrypt/live/\${DOMAIN}/privkey.pem"
        export SSL_CERT_REMOTE SSL_KEY_REMOTE
        nginx_render_and_install
      else
        nginx_install_acme_bootstrap   # port-80 webroot so certbot can validate
        run_certbot                    # certonly --webroot; sets+exports cert paths
        nginx_render_and_install
      fi
    else
      setup_tls_cert                   # provided | self-signed; sets+exports cert paths
      export SSL_CERT_REMOTE SSL_KEY_REMOTE
      nginx_render_and_install
    fi
    ;;
  http-*)
    nginx_render_and_install
    ;;
esac
EOF
}

kb_refresh_start() {
  is_true "${ENABLE_KB_REFRESH}" || return 0
  hr "KB refresh sidecar"
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH"
sg docker -c "cd \$APP_PATH && docker compose --profile kb-refresh up -d kb-refresh" && success "kb-refresh sidecar started" || warn "could not start kb-refresh (is ENABLE_KB set?)"
EOF
}

gvm_note() {
  is_true "${ENABLE_GVM}" || return 0
  hr "GVM"
  warn "GVM enabled: feeds sync 10-20 min before scans work."
  # redamon.sh install (run earlier) is now the single source of truth: it
  # generates a strong GVM_PASSWORD in the server .env AND applies it to the live
  # gvmd 'admin' user (ensure_gvm_secret + reconcile_gvm_admin_password). We do
  # NOT rotate to a fresh random password here — the old code did exactly that and
  # never persisted it, so the app stayed on admin/admin and every GVM scan failed
  # to authenticate. Instead we RE-APPLY the pinned .env value (idempotent: gvmd
  # --new-password needs no old password), which also converges the case where
  # redamon.sh's reconcile timed out waiting for a slow first-boot gvmd.
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH"
GVMPW="\$(grep '^GVM_PASSWORD=' .env 2>/dev/null | head -1 | cut -d= -f2-)"
if [ -z "\$GVMPW" ]; then
  warn "GVM_PASSWORD not found in .env; GVM may still be initialising. Check: grep '^GVM_PASSWORD=' \$APP_PATH/.env"
elif sg docker -c "docker compose exec -T -u gvmd gvmd gvmd --user=admin --new-password='\$GVMPW'" 2>/dev/null; then
  success "GVM admin credentials: admin / \$GVMPW  (also stored as GVM_PASSWORD in \$APP_PATH/.env)"
else
  warn "gvmd not ready to apply the password yet; it converges on the next './redamon.sh update'. Password is in \$APP_PATH/.env (GVM_PASSWORD)."
fi
EOF
}

# ============================================================================
#  post-deploy verification (§12)
# ============================================================================
verify() {
  hr "Verify"
  remote <<EOF || warn "verification reported issues -- review above"
${PREAMBLE}
cd "\$APP_PATH"
rc=0
step "Loopback binds (Local Address column of listening sockets)"
LB=\$(sg docker -c "ss -tlnH" 2>/dev/null | awk '{print \$4}')
for p in 3000 8090; do
  hits=\$(printf '%s\n' "\$LB" | grep -E "[:.]\${p}\b" || true)
  if [ -z "\$hits" ]; then err "port \${p} not listening (webapp/agent down?)"; rc=1;
  elif printf '%s\n' "\$hits" | grep -qvE '^127\.0\.0\.1:|^\[::1\]:'; then err "port \${p} bound off-loopback: \$hits"; rc=1;
  else success "port \${p} loopback-only"; fi
done
step "Internal ports must never bind off-loopback (datastores, orchestrator, 4444 catcher)"
db_bad=0
# 4444 is the reverse-shell catcher: loopback-bound at rest (exposed per-engagement
# only via 'deploy.sh revshell-open', which adds a host-side socat forwarder, not a
# docker port change), so its docker binding must always be loopback here.
for p in 5432 7474 7687 8010 4444; do
  hits=\$(printf '%s\n' "\$LB" | grep -E "[:.]\${p}\b" || true)
  if [ -n "\$hits" ] && printf '%s\n' "\$hits" | grep -qvE '^127\.0\.0\.1:|^\[::1\]:'; then err "port \${p} off-loopback: \$hits"; rc=1; db_bad=1; fi
done
[ "\$db_bad" -eq 0 ] && success "internal ports loopback-only"
step "Container health"
sg docker -c "docker compose ps" || true
# NB: tests/test_port_bindings.sh is a DEV/CI test that asserts webapp(3000),
# agent(8090) and 4444 stay externally ROUTABLE -- the default (local) compose
# posture. The single-origin prod overlay deliberately loopback-binds all three
# (nginx:443 is the only public surface), so that test's expectation is inverted
# here and the loopback checks above are the correct prod assertion. Do NOT run it
# in prod: it would report false failures for the very hardening prod requires.
info "single-origin prod: webapp/agent/4444 loopback by design (dev-only test_port_bindings.sh not run)"
step "Offline OSV database (supply-chain SCA)"
# redamon.sh's ensure_osv_db is deliberately best-effort: a network failure warns
# and lets the stack come up. Without a check here, that warning scrolls past in a
# 40-minute install and the operator only discovers the empty DB when the first
# supply-chain scan reports "no <ecosystem> ecosystem". Warn, never fail: the rest
# of the platform is fully functional without it, and an air-gapped host that set
# OSV_DB_AUTO_REFRESH=false has an empty DB on purpose.
osv_mp=\$(sg docker -c "docker volume inspect -f '{{.Mountpoint}}' redamon-osv-db" 2>/dev/null || true)
if [ -z "\$osv_mp" ]; then
  warn "redamon-osv-db volume missing -- supply-chain scans cannot verdict anything (run './redamon.sh supply-chain-sync')"
elif [ "\$(run_sudo ls -1 "\$osv_mp" 2>/dev/null | grep -c '^\.redamon_synced_')" -eq 0 ]; then
  if is_true "\${OSV_DB_AUTO_REFRESH:-true}"; then
    warn "offline OSV database is EMPTY -- supply-chain scans will report a missing ecosystem. Re-run: ./redamon.sh supply-chain-sync"
  else
    info "offline OSV database empty; OSV_DB_AUTO_REFRESH=false, so this is intentional"
  fi
else
  success "OSV database synced: \$(run_sudo ls -1 "\$osv_mp" 2>/dev/null | sed -n 's/^\.redamon_synced_//p' | tr '\n' ' ')"
fi
step "Agent in the Loop switch"
# Both services read it: the agent opens steps, the webapp serves the loop_* tools.
# The switch defaults on here, so deploy assets newer than the app (a REPO_BRANCH
# from before the feature) must not fail verify on a flag that app never passes.
if ! grep -q AGENT_IN_THE_LOOP_ENABLED "\$APP_PATH/docker-compose.yml" 2>/dev/null; then
  info "Agent in the Loop: not in this app version (skipped)"
elif is_true "\${AGENT_IN_THE_LOOP_ENABLED:-false}"; then
  for svc in agent webapp; do
    v=\$(sg docker -c "docker compose exec -T \$svc printenv AGENT_IN_THE_LOOP_ENABLED" 2>/dev/null | tr -d '[:space:]')
    if is_true "\$v"; then success "\$svc has AGENT_IN_THE_LOOP_ENABLED=true"
    else err "AGENT_IN_THE_LOOP_ENABLED=true but the flag did not reach the \$svc container (seed/plumbing)"; rc=1; fi
  done
else
  info "Agent in the Loop off (as configured)"
fi
step "Admin present"
cnt=\$(sg docker -c "docker compose exec -T webapp node scripts/check-admin.mjs" 2>/dev/null | tr -d '[:space:]')
[ "\${cnt:-0}" -ge 1 ] 2>/dev/null && success "admin count = \${cnt}" || { err "no admin user found"; rc=1; }
exit \$rc
EOF
  # Public-surface checks from the operator machine
  if [[ "${ACCESS_MODE}" == https-* ]]; then
    local code; code=$(curl -m 15 -skS -o /dev/null -w '%{http_code}' "https://${PUBLIC_HOST}/api/health" 2>/dev/null || echo "000")
    [[ "${code}" == "200" ]] && ok "https://${PUBLIC_HOST}/api/health -> 200" || warn "health check -> ${code} (allowlist/DNS/cert may still be settling)"
  else
    local code; code=$(curl -m 15 -sS -o /dev/null -w '%{http_code}' "http://${PUBLIC_HOST}/api/health" 2>/dev/null || echo "000")
    [[ "${code}" == "200" ]] && ok "http://${PUBLIC_HOST}/api/health -> 200" || warn "health check -> ${code}"
  fi

  # Inbound MCP surface. Cheap to probe unauthenticated because the route
  # answers with DISTINGUISHABLE codes, which is what lets this tell the four
  # silent failure modes apart instead of lumping them into "inert endpoint":
  #   404 = disabled (flag off, or the flag never reached the container)
  #   401 = enabled, credential required  <- the working state
  #   403 = the basic_auth gate ate the Authorization header
  #   200 = enabled with NO credential required, which must never happen
  local base="${HTTP_SCHEME}://${PUBLIC_HOST}"
  local mcp; mcp=$(curl -m 15 -skS -o /dev/null -w '%{http_code}' \
      -X POST "${base}/api/mcp-server" \
      -H 'Content-Type: application/json' \
      -H 'Accept: application/json, text/event-stream' \
      -d '{"jsonrpc":"2.0","method":"tools/list","id":1}' 2>/dev/null || echo "000")
  if is_true "${MCP_SERVER_ENABLED}"; then
    case "${mcp}" in
      401) ok "MCP /api/mcp-server -> 401 (enabled, credential required)" ;;
      403) err "MCP -> 403: the edge gate is eating the Authorization header. Set MCP_EDGE_ALLOW_BEARER=true (GATE_MODE=${GATE_MODE})"; ;;
      404) err "MCP -> 404 but MCP_SERVER_ENABLED=true: the flag did not reach the webapp container (seed/plumbing)" ;;
      200) err "MCP -> 200 WITHOUT a token: the endpoint is answering unauthenticated. Stop and investigate." ;;
      000) warn "MCP probe could not connect (firewall/allowlist may be excluding this machine)" ;;
      *)   warn "MCP -> ${mcp} (unexpected)" ;;
    esac
  else
    case "${mcp}" in
      404) ok "MCP disabled -> 404 (as configured)" ;;
      401) err "MCP is configured off but /api/mcp-server -> 401: the webapp has it ON. Check MCP_SERVER_ENABLED in the server's app .env and re-run update" ;;
      *)   warn "MCP is disabled but /api/mcp-server -> ${mcp} (expected 404)" ;;
    esac
  fi

  # Stateless mode has no stream to manage, so GET must be refused.
  local mget; mget=$(curl -m 15 -skS -o /dev/null -w '%{http_code}' "${base}/api/mcp-server" 2>/dev/null || echo "000")
  if is_true "${MCP_SERVER_ENABLED}"; then
    [[ "${mget}" == "405" ]] && ok "MCP GET -> 405" || warn "MCP GET -> ${mget} (expected 405)"
  fi

  # Regression guard for the path collision: /api/mcp/* is the OUTBOUND plugin
  # admin namespace and must still require a session. A PUBLIC_PATHS entry of
  # '/api/mcp' would have made all three public, since the middleware matches
  # on startsWith(p + '/').
  local adm; adm=$(curl -m 15 -skS -o /dev/null -w '%{http_code}' "${base}/api/mcp/manifest" 2>/dev/null || echo "000")
  case "${adm}" in
    401|403) ok "/api/mcp/manifest -> ${adm} (outbound admin still gated)" ;;
    200) err "/api/mcp/manifest -> 200 UNAUTHENTICATED: the outbound MCP admin namespace is exposed" ;;
    *) warn "/api/mcp/manifest -> ${adm}" ;;
  esac
}

# ============================================================================
#  MODE: update
# ============================================================================
cmd_update() {
  hr "UPDATE ${HOST_IP} (pull latest ${REPO_BRANCH} HEAD + apply)"
  ship_assets
  # Before the pull: redamon.sh refuses an Engine older than 28.0.0, and a server set up
  # before that requirement would otherwise stop halfway through the update. A no-op on
  # a current Engine and Compose.
  hr "Docker Engine + Compose (upgraded only when too old)"
  remote <<EOF
${PREAMBLE}
source modules/host_bootstrap.sh
bootstrap_docker
EOF
  hr "Pull --ff-only + diff-driven rebuild via redamon.sh update"
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH"
[ -d .git ] || { err "no checkout at \$APP_PATH -- run 'init' first"; exit 1; }
export DOMAIN NEXT_PUBLIC_AGENT_WS_URL AGENT_CORS_ORIGINS WEBAPP_NODE_ENV
[ -n "\${REDAMON_VERSION}" ] && export REDAMON_VERSION
is_true "\${ENABLE_ZRAM}" && export REDAMON_ENABLE_ZRAM=1
[ -n "\${REDAMON_BUILD_PARALLEL}" ] && export REDAMON_BUILD_PARALLEL
# No source patches to reset: webapp's single-origin WS URL is a first-class ARG in the
# base Dockerfile (NEXT_PUBLIC_AGENT_WS_URL), baked from the prod overlay's build-arg, so
# redamon.sh's own diff-driven webapp rebuild bakes it correctly. The old reset -> pull ->
# re-apply-patch -> rebuild dance is gone -- it could leave the Dockerfile unpatched and
# ship the wrong ws://localhost:8090 WS URL (the chat "Connecting..." bug).
# Preserve the version stamp so the overlay build-arg doesn't default to 0.0.0.
[ -z "\${REDAMON_VERSION:-}" ] && [ -f VERSION ] && export REDAMON_VERSION="\$(cat VERSION 2>/dev/null || echo)"
step "Re-seed application .env (operator app-config; init-only before, so update ignored it)"
touch .env
# A key is appended on a line of its own even when the operator's .env has no final newline.
seed() { local k="\$1" v="\$2"; [ -z "\$v" ] && return 0; grep -q "^\$k=" .env && sed -i "s|^\$k=.*|\$k=\$v|" .env || { [ -z "\$(tail -c1 .env)" ] || echo >> .env; echo "\$k=\$v" >> .env; }; }
# Inbound MCP server. Seeded BEFORE redamon.sh runs: ensure_auth_secrets appends
# MCP_SERVER_ENABLED=false when the key is ABSENT, so without this the deployed
# host actively pins the flag off and the operator's choice is unreachable.
# seed() overwrites an existing key, so re-running is idempotent either way.
seed MCP_SERVER_ENABLED "\${MCP_SERVER_ENABLED}"
# Marks this .env as a deployed server: redamon.sh then never turns its MCP server on.
seed REDAMON_SINGLE_HOST_DEPLOY true
seed MCP_TOKEN_RETENTION_DAYS "\${MCP_TOKEN_RETENTION_DAYS}"
seed MCP_LLM_DAILY_BUDGET "\${MCP_LLM_DAILY_BUDGET}"
seed MCP_RATE_MUTE_PER_MIN "\${MCP_RATE_MUTE_PER_MIN}"
seed MCP_RATE_READ_PER_MIN "\${MCP_RATE_READ_PER_MIN}"
seed MCP_RATE_QUERY_PER_MIN "\${MCP_RATE_QUERY_PER_MIN}"
seed MCP_RATE_WRITE_PER_MIN "\${MCP_RATE_WRITE_PER_MIN}"
seed MCP_RATE_START_PER_WINDOW "\${MCP_RATE_START_PER_WINDOW}"
seed MCP_RATE_START_WINDOW_MS "\${MCP_RATE_START_WINDOW_MS}"
seed MCP_RATE_COMPARE_PER_WINDOW "\${MCP_RATE_COMPARE_PER_WINDOW}"
seed MCP_RATE_COMPARE_WINDOW_MS "\${MCP_RATE_COMPARE_WINDOW_MS}"
seed MCP_KALI_EXEC_ENABLED "\${MCP_KALI_EXEC_ENABLED}"
seed MCP_RATE_EXEC_PER_MIN "\${MCP_RATE_EXEC_PER_MIN}"
seed AGENT_IN_THE_LOOP_ENABLED "\${AGENT_IN_THE_LOOP_ENABLED}"
seed MCP_RATE_LOOP_PER_MIN "\${MCP_RATE_LOOP_PER_MIN}"
seed MCP_DISABLED_TOOLS "\${MCP_DISABLED_TOOLS}"
seed MCP_TOKEN_PRUNE_INTERVAL "\${MCP_TOKEN_PRUNE_INTERVAL}"
# The webapp validates the request Origin against its own URL, which nginx
# builds from \`proxy_set_header Host \$host\` -- and \$host DROPS THE PORT. On a
# non-default HTTPS_PORT an Origin-sending client would be 403'd against its own
# origin, so the public origin is passed explicitly.
seed MCP_ALLOWED_ORIGIN "\${MCP_PUBLIC_ORIGIN}"
# The plugin routes check the request Origin like the MCP route, hence the same
# derived origin.
seed PLUGINS_ALLOWED_ORIGIN "\${MCP_PUBLIC_ORIGIN}"
# Behind nginx every request arrives from 127.0.0.1 unless the app is told the
# edge is trusted. nginx pins X-Forwarded-For to the real peer, so this is safe
# here and is what makes audit records and the login lockout name a real IP.
seed TRUST_PROXY "true"

step "redamon.sh update (git pull --ff-only + diff-driven rebuild + secret regen)"
sg docker -c "cd \$APP_PATH && ./redamon.sh update"
# redamon.sh rebuilds only what CHANGED. An .env-only edit changes no image, so
# the webapp would keep running with its old environment; recreate it explicitly.
step "Recreate webapp so a changed .env actually takes effect"
# Explicit -f files ignore COMPOSE_FILE, where redamon.sh adds the plugins overlay; without
# it here, every update would take the webapp off its plugin network and volume.
sg docker -c "cd \$APP_PATH && docker compose -f docker-compose.yml -f \$OVERLAY_DIR/docker-compose.prod.yml -f docker-compose.plugins.yml up -d webapp"
EOF
  run_secrets_gate
  # nginx may have changed; re-render is idempotent + gated
  setup_nginx_tls
  verify
  ok "UPDATE complete"
}

# ============================================================================
#  secondary verbs
# ============================================================================
cmd_status() {
  hr "STATUS ${HOST_IP}"
  ship_assets   # refresh modules/deploy.env/overlay (survives a host reboot clearing /tmp)
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH" 2>/dev/null || { err "no checkout"; exit 1; }
sg docker -c "cd \$APP_PATH && ./redamon.sh status" || true
sg docker -c "docker compose ps" || true
run_sudo ufw status verbose 2>/dev/null || true
run_sudo nginx -t 2>&1 || true
if [ -d /etc/letsencrypt/live ]; then run_sudo openssl x509 -enddate -noout -in /etc/letsencrypt/live/*/fullchain.pem 2>/dev/null || true; fi
EOF
}

cmd_harden() {
  hr "HARDEN ${HOST_IP} (re-apply host hardening + nginx, no rebuild)"
  ship_assets
  remote <<EOF
${PREAMBLE}
source modules/host_bootstrap.sh
source modules/ssh_hardening.sh
source modules/firewall.sh
source modules/fail2ban.sh
source modules/unattended_upgrades.sh
host_bootstrap
setup_ssh_hardening
setup_firewall
setup_fail2ban
setup_unattended_upgrades
EOF
  setup_nginx_tls
  ok "Harden complete"
}

cmd_ssl_renew() {
  hr "SSL-RENEW ${HOST_IP}"
  ship_assets
  remote <<EOF
${PREAMBLE}
source modules/tls.sh
export TLS_MODE DOMAIN HOST_IP SSL_KEY_PASSWORD
renew_tls
EOF
  ok "ssl-renew complete"
}

cmd_down() {
  hr "DOWN ${HOST_IP} (stop stack, keep volumes/images)"
  ship_assets
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH" 2>/dev/null || { err "no checkout"; exit 1; }
sg docker -c "cd \$APP_PATH && ./redamon.sh down"
EOF
  ok "Stack stopped (data preserved)"
}

# ============================================================================
#  Reverse-shell (4444) engagement exposure -- host-side socat forwarder + ufw scope.
#  The container keeps 4444 on loopback (prod overlay); a transient systemd unit runs
#  `socat <primary-ip>:4444 -> 127.0.0.1:4444` so the port is a HOST listener that ufw
#  (INPUT chain) can source-scope -- unlike a Docker-published port, which bypasses ufw.
#  A reboot drops the transient unit, so the catcher fails CLOSED.
# ============================================================================
cmd_revshell_open() {
  [[ -n "${REVSHELL_TARGET_CIDRS}" ]] || die "revshell-open requires REVSHELL_TARGET_CIDRS (your RoE target scope) in .env -- never expose 4444 unscoped"
  hr "REVSHELL-OPEN ${HOST_IP}  (4444 -> RoE targets: ${REVSHELL_TARGET_CIDRS})"
  warn "The msf handler on 4444 is UNAUTHENTICATED. Exposing it to anything beyond your"
  warn "signed RoE target scope is dangerous. Run 'revshell-close' the moment you are done."
  ship_assets
  remote <<EOF
${PREAMBLE}
[ -n "\${REVSHELL_TARGET_CIDRS}" ] || { err "REVSHELL_TARGET_CIDRS empty"; exit 1; }
install_if_missing socat
PRIMARY_IP=\$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if(\$i=="src"){print \$(i+1); exit}}')
[ -n "\${PRIMARY_IP}" ] || { err "could not detect the host primary IP to bind socat"; exit 1; }
step "ufw: scope host port 4444 to the RoE target CIDRs"
if is_true "\${ENABLE_UFW}"; then
  IFS=',' read -ra _cidrs <<< "\${REVSHELL_TARGET_CIDRS}"
  for c in "\${_cidrs[@]}"; do c=\$(echo "\$c" | xargs); [ -n "\$c" ] && run_sudo ufw allow from "\$c" to any port 4444 proto tcp; done
else
  warn "ENABLE_UFW=false -- 4444 will be reachable from ANY source that can hit \${PRIMARY_IP}. Enforce scoping in your cloud Security Group."
fi
step "Start the transient 4444 forwarder (auto-removed on stop/reboot)"
run_sudo systemctl stop redamon-revshell 2>/dev/null || true
run_sudo systemctl reset-failed redamon-revshell 2>/dev/null || true
run_sudo systemd-run --unit=redamon-revshell --collect --description="RedAmon reverse-shell 4444 forwarder" \
  /usr/bin/socat "TCP-LISTEN:4444,bind=\${PRIMARY_IP},fork,reuseaddr" TCP:127.0.0.1:4444
sleep 1
if run_sudo systemctl is-active --quiet redamon-revshell; then
  success "4444 OPEN on \${PRIMARY_IP} (scoped to \${REVSHELL_TARGET_CIDRS}) -> 127.0.0.1:4444 (kali msf handler)"
  info "Set your payload LHOST to the host's public IP, LPORT 4444, and start the msf handler in RedAmon."
  warn "Run './deploy.sh revshell-close' when the engagement ends. A reboot also auto-closes it."
else
  err "socat forwarder failed to start"; run_sudo journalctl -u redamon-revshell -n 20 --no-pager 2>/dev/null || true; exit 1
fi
EOF
  ok "revshell-open complete"
}

cmd_revshell_close() {
  hr "REVSHELL-CLOSE ${HOST_IP} (stop 4444 forwarder, re-scope to loopback-only)"
  ship_assets
  remote <<EOF
${PREAMBLE}
step "Stop the 4444 forwarder"
run_sudo systemctl stop redamon-revshell 2>/dev/null || true
run_sudo systemctl reset-failed redamon-revshell 2>/dev/null || true
step "Remove ufw 4444 allow rules"
if is_true "\${ENABLE_UFW}"; then
  IFS=',' read -ra _cidrs <<< "\${REVSHELL_TARGET_CIDRS:-}"
  for c in "\${_cidrs[@]}"; do c=\$(echo "\$c" | xargs); [ -n "\$c" ] && run_sudo ufw delete allow from "\$c" to any port 4444 proto tcp 2>/dev/null || true; done
  run_sudo ufw --force delete allow 4444/tcp 2>/dev/null || true
fi
success "4444 forwarder stopped; reverse-shell catcher is back to loopback-only"
EOF
  ok "revshell-close complete"
}

cmd_logs() {
  hr "LOGS ${HOST_IP} :: ${LOGS_SERVICE}"
  ship_assets
  remote <<EOF
${PREAMBLE}
cd "\$APP_PATH" 2>/dev/null || { err "no checkout"; exit 1; }
sg docker -c "cd \$APP_PATH && docker compose logs -f --tail=200 ${LOGS_SERVICE}"
EOF
}

# ============================================================================
#  main
# ============================================================================
main() {
  preflight_validate
  if is_true "${DRY_RUN}"; then
    hr "DRY RUN -- resolved plan (no host mutation)"
    cat <<PLAN
MODE=${MODE}  HOST=${HOST_IP}:${SSH_PORT}  USER=${REMOTE_USER}
ACCESS_MODE=${ACCESS_MODE}  TLS_MODE=${TLS_MODE}  PUBLIC_HOST=${PUBLIC_HOST}
WS=${NEXT_PUBLIC_AGENT_WS_URL}  CORS=${AGENT_CORS_ORIGINS}  gate=${GATE_MODE}
MCP=${MCP_SERVER_ENABLED}  mcp_edge_bearer=${MCP_EDGE_ALLOW_BEARER}  mcp_cidrs=${MCP_CLIENT_CIDRS:-<none>}  origin=${MCP_PUBLIC_ORIGIN}
flags: GVM=${ENABLE_GVM} KB=${ENABLE_KB} ZRAM=${ENABLE_ZRAM} ufw=${ENABLE_UFW}
PLAN
    exit 0
  fi
  setup_ssh
  case "${MODE}" in
    init)      cmd_init ;;
    update)    cmd_update ;;
    status)    cmd_status ;;
    harden)    cmd_harden ;;
    ssl-renew) cmd_ssl_renew ;;
    down)      cmd_down ;;
    logs)      cmd_logs ;;
    revshell-open)  cmd_revshell_open ;;
    revshell-close) cmd_revshell_close ;;
  esac
}
# Run main only when EXECUTED, never when SOURCED. Sourcing is how
# tests/deploy_mcp_env_chain_test.sh exercises build_deploy_env and the
# ACCESS_MODE derivations for real, without needing an SSH host.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  main
fi
