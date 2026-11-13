#!/usr/bin/env bash
# =============================================================================
# Aggregator for the Kali MCP auth + loopback + DB-secret hardening tests
# (STRIDE S10 / E1 / I9 / S13). Runs every tier in order and exits non-zero on
# the first failure. Suites that need a running stack skip themselves cleanly.
#
#   bash tests/run_security_remediation_suite.sh
# =============================================================================
set -uo pipefail
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

FAILED=0
run() {
    echo
    echo "############################################################"
    echo "# $1"
    echo "############################################################"
    shift
    if "$@"; then echo ">> OK"; else echo ">> FAILED"; FAILED=1; fi
}

# Unit / integration (no running stack required)
run "Unit: redamon.sh secret generation"        bash tests/redamon_secrets_test.sh
run "Integration: host-port publish policy"      bash tests/test_port_bindings.sh
run "Unit: docker-broker policy (T1/T2 mode)"    python3 services/docker_broker/test_policy.py
run "Unit: MCP bearer middleware (ASGI)"         python3 mcp/servers/tests/test_auth_middleware.py
run "Unit: agent MCP client auth wiring"         python3 agentic/tests/test_system_mcp_auth.py
run "Integration: SSE auth round-trip (real MCP)" python3 mcp/servers/tests/test_sse_auth_integration.py

# S6/I14 host-runnable guard units (container-bound integration parts self-skip).
# Full agent-side suites run via ./agentic/run_tests.sh; recon SSRF integration
# runs in the recon image; webapp routes via `npx vitest run`.
run "Unit: WS ticket verification (S6/S2)"       python3 agentic/tests/test_ws_ticket_auth.py
run "Unit: JS-recon SSRF URL guard (I14)"        python3 recon/tests/test_js_recon_ssrf.py

# --- Wave 2 (STRIDE remediation wave 2) host-runnable suites ---
run "Unit: WS same-origin + ticket gate (S3/S4)" python3 agentic/tests/test_ws_origin_auth.py
run "Unit: broker ownership gating (E1)"          python3 services/docker_broker/test_ownership.py
run "Unit: broker plumbing regression"            python3 services/docker_broker/test_plumbing.py
run "Unit: scan admission caps (D3)"              python3 tests/test_admission_ledger.py
run "Unit: redagraph tenant + scanner key (S8)"   python3 tests/test_redagraph.py
run "Unit: github-hunt stdout redaction (I4)"     python3 tests/test_github_hunt_redaction.py
run "Unit: deploy patch integrity (T3)"           bash tests/deploy_patch_integrity_test.sh
run "Unit: deploy.env cleanup (I7)"               bash tests/deploy_env_cleanup_test.sh

# --- Agent-image-bound suites (need the baked deps; skip if image absent) ---
if docker image inspect redamon-agent >/dev/null 2>&1; then
    # The gate's runner, not a mount of agentic/ over /app: that hides every folder the
    # image bakes in beside it (recon_settings/, knowledge_base/), and `import api` fails.
    agent_test() { "$REPO_ROOT/agentic/run_tests.sh" "$@"; }
    run "Agent: /graph/exec auth + apoc.atomic (S8)" agent_test tests/test_graph_exec.py
    run "Agent: fs_extract zip caps (D10)"           agent_test tests/test_fs_extract_caps.py
    run "Agent: log redaction + generic error (I5)"  agent_test tests/test_log_redaction.py
    run "Agent: stdio child holds no credential (GHSA-j3r5)" agent_test tests/test_ghsa_j3r5_member_stdio_mcp.py
else
    echo ">> SKIP agent-image suites (redamon-agent image not built)"
fi

# --- Webapp vitest suites (run if node_modules present) ---
if [[ -x "$REPO_ROOT/webapp/node_modules/.bin/vitest" ]]; then
    webapp_vitest() { ( cd "$REPO_ROOT/webapp" && ./node_modules/.bin/vitest run --no-file-parallelism "$@" ); }
    run "Webapp: audit/auth/login/import routes (R1/R2/R5/S11/S12/D10)" webapp_vitest \
        src/lib/audit.test.ts src/lib/loginThrottle.test.ts \
        src/app/api/auth/login/route.test.ts src/app/api/auth/logout/route.test.ts \
        src/app/api/auth/act-as/route.test.ts src/app/api/projects/import/route.test.ts
    run "Webapp: a member's stdio MCP draft is refused (GHSA-j3r5)" webapp_vitest \
        src/app/api/mcp/test/ghsa-j3r5-x2gg-2hgv.test.ts
else
    echo ">> SKIP webapp vitest suites (webapp/node_modules absent)"
fi

# Security (skips if stack down)
run "Security: reported exploit is blocked"      bash tests/test_exploit_blocked.sh
run "Live E2E: S6 WS hijack + I1 + I19 tunnel"   bash tests/test_e2e_security_live.sh
run "Live E2E: member stdio MCP draft (GHSA-j3r5)" bash tests/test_ghsa_j3r5_live.sh

echo
echo "============================================================"
if [[ $FAILED -eq 0 ]]; then
    echo "ALL SECURITY-REMEDIATION SUITES GREEN"
else
    echo "SECURITY-REMEDIATION SUITES: FAILURES ABOVE"
fi
exit $FAILED
