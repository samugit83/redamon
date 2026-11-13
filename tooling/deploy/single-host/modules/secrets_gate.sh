#!/usr/bin/env bash
# secrets_gate.sh -- fail the deploy on weak/default/unset secrets (§8.5).
# Runs on the host in the app dir. Verifies the secrets redamon.sh generated; it does
# NOT set them. Requires _common.sh.
#
# MCP_AUTH_TOKEN, AGENT_WS_TICKET_SECRET and TUNNEL_AUTH_TOKEN fail closed when unset:
# the Kali servers, the agent WebSocket and the tunnel manager refuse every request, so
# those features stop working instead of opening up. On a public host every secret must
# be strong.

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
