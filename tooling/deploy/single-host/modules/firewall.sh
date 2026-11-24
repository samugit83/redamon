#!/usr/bin/env bash
# firewall.sh -- ufw as the portable host firewall (§10).
# Reads (exported by deploy.sh): MCP_SERVER_ENABLED, MCP_CLIENT_CIDRS, ENABLE_UFW, HTTP_PORT, HTTPS_PORT, SSH_PORT,
#   SSH_ALLOW_CIDRS (falls back to OPERATOR_ALLOW_CIDRS), OPERATOR_ALLOW_CIDRS,
#   ACCESS_MODE, REVSHELL_TARGET_CIDRS.
# Requires _common.sh.
#
# Docker-bypass caveat: Docker publishes ports via its own iptables chains and can
# bypass ufw. The loopback re-binds in the prod overlay are the REAL control for
# 3000/8090, and the orchestrator binds each Kali sandbox's optional pool port on
# 127.0.0.1; ufw here is belt-and-braces + the SSH lockdown.

# Admit the MCP client CIDRs to the app port, on top of the operator CIDRs.
#
# The firewall cannot filter by URL path, so this necessarily opens the PORT to
# those sources. The path-level narrowing is nginx's job: the exact-match
# `location = /api/mcp-server` re-states its own allow/deny, so an MCP client
# CIDR reaches the MCP endpoint and nothing else. Without this, ufw drops the
# agent's packet before nginx ever sees the path, and MCP_EDGE_ALLOW_BEARER is
# necessary but not sufficient.
#
# Only meaningful when OPERATOR_ALLOW_CIDRS is set; with no operator list the
# port is already world-open and there is nothing extra to admit.
_allow_mcp_clients() {
  local port="$1"
  is_true "${MCP_SERVER_ENABLED:-false}" || return 0
  [[ -n "${MCP_CLIENT_CIDRS:-}" ]] || return 0
  info "MCP client CIDRs also allowed on ${port}: ${MCP_CLIENT_CIDRS} (nginx narrows them to /api/mcp-server)"
  _ufw_allow_sources "${MCP_CLIENT_CIDRS}" "${port}" tcp
}

_ufw_allow_sources() {
  # $1 = comma-list of CIDRs, $2 = port, $3 = proto
  local cidrs="$1" port="$2" proto="$3" cidr
  if [[ -z "${cidrs}" ]]; then
    run_sudo ufw allow "${port}/${proto}"
    return
  fi
  IFS=',' read -ra arr <<< "${cidrs}"
  for cidr in "${arr[@]}"; do
    cidr="$(echo "$cidr" | xargs)"
    [[ -z "$cidr" ]] && continue
    run_sudo ufw allow from "$cidr" to any port "$port" proto "$proto"
  done
}

setup_firewall() {
  if ! is_true "${ENABLE_UFW:-true}"; then
    disable_firewall
    return 0
  fi
  step "Firewall (ufw)"

  local ssh_port="${SSH_PORT:-22}"
  local http_port="${HTTP_PORT:-80}"
  local https_port="${HTTPS_PORT:-443}"
  local ssh_cidrs="${SSH_ALLOW_CIDRS:-}"
  [[ -z "${ssh_cidrs}" ]] && ssh_cidrs="${OPERATOR_ALLOW_CIDRS:-}"

  run_sudo ufw --force reset >/dev/null 2>&1 || true
  run_sudo ufw default deny incoming
  run_sudo ufw default allow outgoing

  # SSH: operator CIDRs only (or open if none supplied -- warn loudly)
  if [[ -z "${ssh_cidrs}" ]]; then
    warn "No SSH_ALLOW_CIDRS / OPERATOR_ALLOW_CIDRS set -- opening SSH to the world (NOT recommended)"
    run_sudo ufw allow "${ssh_port}/tcp"
  else
    info "SSH (${ssh_port}) restricted to: ${ssh_cidrs}"
    _ufw_allow_sources "${ssh_cidrs}" "${ssh_port}" tcp
  fi

  if [[ "${ACCESS_MODE:-https-domain}" == http-* ]]; then
    # http-* lab mode: the app is served on HTTP_PORT (no TLS, no ACME). Scope it to the
    # operator CIDRs when supplied (defense-in-depth on top of the nginx gate).
    if [[ -n "${OPERATOR_ALLOW_CIDRS:-}" ]]; then
      info "HTTP app (${http_port}) restricted to operator CIDRs: ${OPERATOR_ALLOW_CIDRS}"
      _ufw_allow_sources "${OPERATOR_ALLOW_CIDRS}" "${http_port}" tcp
      _allow_mcp_clients "${http_port}"
    else
      warn "No OPERATOR_ALLOW_CIDRS -- opening HTTP app (${http_port}) to the world (nginx gate is the only brake)"
      run_sudo ufw allow "${http_port}/tcp"
    fi
  else
    # https-* : HTTP (80) stays world-open for Let's Encrypt http-01 (LE validates from
    # arbitrary IPs) and the HTTP->HTTPS redirect. HTTPS (the app) is scoped to the
    # operator CIDRs when supplied; world-open only if none given.
    run_sudo ufw allow "${http_port}/tcp"
    if [[ -n "${OPERATOR_ALLOW_CIDRS:-}" ]]; then
      info "HTTPS (${https_port}) restricted to operator CIDRs: ${OPERATOR_ALLOW_CIDRS}"
      _ufw_allow_sources "${OPERATOR_ALLOW_CIDRS}" "${https_port}" tcp
      _allow_mcp_clients "${https_port}"
    else
      warn "No OPERATOR_ALLOW_CIDRS -- opening HTTPS (${https_port}) to the world (nginx gate is the only brake)"
      run_sudo ufw allow "${https_port}/tcp"
    fi
  fi

  # The reverse-shell ports stay CLOSED at the firewall here. Each Kali sandbox publishes at
  # most one port of KALI_SANDBOX_PORT_POOL, on 127.0.0.1 (deploy.sh refuses any other bind
  # address), so none is externally reachable. Per-engagement exposure is handled by
  # `./deploy.sh revshell-open`, which starts one host-side socat forwarder per pool port (a
  # real INPUT-chain listener ufw can scope) and opens the range to REVSHELL_TARGET_CIDRS,
  # then `revshell-close` tears them back down. See the README "Reverse shells" bullet.
  info "the reverse-shell port pool stays closed here; use './deploy.sh revshell-open' per engagement"

  run_sudo ufw --force enable
  run_sudo ufw status verbose || true
  success "ufw active"
}

disable_firewall() {
  info "Firewall DISABLED (ENABLE_UFW=false) -- relying on the cloud Security Group + loopback binds"
  run_sudo ufw --force disable >/dev/null 2>&1 || true
}
