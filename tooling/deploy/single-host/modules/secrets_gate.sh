#!/usr/bin/env bash
# secrets_gate.sh -- fail the deploy on weak/default/unset secrets (§8.5).
# Runs on the host in the app dir. Verifies the secrets redamon.sh generated; it does
# NOT set them. Requires _common.sh.
#
# AGENT_WS_TICKET_SECRET fails closed when unset: the agent WebSocket refuses every
# request, so it stops working instead of opening up. MCP_AUTH_TOKEN and TUNNEL_AUTH_TOKEN
# are read by nothing on a release with per-user sandboxes (the orchestrator gives each
# sandbox its own pair), but redamon.sh still generates them, and on an older checkout
# they are the shared Kali container's and tunnel manager's only credential, so they stay
# checked. On a public host every secret must be strong.

secrets_gate() {
  local env_file="${1:?usage: secrets_gate <path-to-.env>}"
  step "Secrets gate"
  if [[ ! -f "${env_file}" ]]; then
    err "secrets gate: ${env_file} not found"
    return 1
  fi

  local vars=(AUTH_SECRET INTERNAL_API_KEY SCANNER_API_KEY ORCHESTRATOR_API_KEY
              MCP_AUTH_TOKEN AGENT_WS_TICKET_SECRET TUNNEL_AUTH_TOKEN
              PLUGIN_RUNNER_KEY PLUGIN_CALL_TOKEN_SECRET
              POSTGRES_PASSWORD NEO4J_PASSWORD)
  local v val fail=0
  for v in "${vars[@]}"; do
    val=$(grep -E "^${v}=" "${env_file}" | head -1 | cut -d= -f2- | tr -d '\r')
    # strip ONE pair of surrounding quotes only (preserve interior chars incl. spaces)
    val=${val%\"}; val=${val#\"}; val=${val%\'}; val=${val#\'}
    case "${val}" in
      ""|changeme|changeme123|redamon_secret|admin|password|secret)
        err "FATAL: ${v} is unset or a known-default value"
        fail=1; continue ;;
    esac
    if [[ ${#val} -lt 24 ]]; then
      err "FATAL: ${v} too short (${#val} chars, need >= 24)"
      fail=1
    fi
  done

  if [[ "${fail}" -ne 0 ]]; then
    err "Secrets gate FAILED -- refusing to expose a host with weak secrets"
    return 1
  fi
  success "Secrets gate passed (all ${#vars[@]} secrets strong)"
}
