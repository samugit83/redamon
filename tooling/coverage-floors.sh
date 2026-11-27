# Zero floors are pending measurement; see docs/readmes/README.TESTING.md.
redamon_coverage_floor() {
    case "$1" in
        agent) echo 79 ;;
        root-agent|root-recon|recon|recon_orchestrator|ai_attack_surface|capture_proxy|docker_broker|plugin_runner) echo 0 ;;
        *) echo "Unknown coverage section: $1" >&2; return 1 ;;
    esac
}
