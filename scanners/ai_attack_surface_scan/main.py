"""AI Attack Surface scan — container entrypoint (Step 2: skeleton).

Control flow (shared spine; no tool yet). Phases are numbered in execution
order so the orchestrator's SSE progress only ever advances:
  [Phase 1] Safety / bounds  — RoE + bounds + hard-guardrail floor (fail fast)
  [Phase 2] Target loading   — read selected AI nodes from the graph
  [Phase 3] Attack           — (skeleton) emit one dummy finding per target
  [Phase 4] Findings         — normalize -> Vulnerability, link to Endpoint

The phase markers are printed to stdout so the orchestrator's SSE layer (Step 3)
can pick them up, mirroring the gvm/trufflehog log conventions.
"""
from __future__ import annotations

import logging
import re
import sys
from pathlib import Path

from config import load_config
from graph import make_driver, verify_connection
from normalizer import make_dummy_finding, write_finding
from safety import SafetyError, enforce
from target_loader import ScopeRefused, ip_mode_scope, load_targets

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("ai-attack-surface")


def _safe_slug(text: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_.-]", "_", text or "target")[:80]


def run_tool(cfg, targets) -> list:
    """Dispatch the configured tool against the targets -> list[Finding].

    Each adapter is failure-soft: a tool that errors on one target yields no
    findings for it but does not abort the run.
    """
    if cfg.tool == "garak":
        from adapters.garak import run as run_garak
        out_base = Path("/app/ai_attack_surface_scan/output") / (cfg.run_id or "dev")
        findings = []
        for t in targets:
            gdir = out_base / "garak" / _safe_slug(f"{t.baseurl}{t.path}")
            try:
                findings.extend(run_garak(
                    t, cfg.bounds, str(gdir), cfg.run_id,
                    judge_base_url=cfg.judge_base_url or None,
                    target_model=cfg.target_model or None,
                    api_key=cfg.api_key or None,
                    auth_header=cfg.auth_header or None,
                    auth_scheme=cfg.auth_scheme or None,
                    probes=cfg.probes or None,
                ))
            except Exception as e:  # one target failing must not abort the job
                log.exception(f"garak failed on {t.url}: {e}")
                print(f"    [!] garak failed on {t.url}: {e}")
        return findings

    if cfg.tool == "pyrit":
        from adapters.pyrit import run as run_pyrit
        out_base = Path("/app/ai_attack_surface_scan/output") / (cfg.run_id or "dev")
        findings = []
        for t in targets:
            pdir = out_base / "pyrit" / _safe_slug(f"{t.baseurl}{t.path}")
            try:
                findings.extend(run_pyrit(
                    t, cfg.bounds, str(pdir), cfg.run_id,
                    judge_base_url=cfg.judge_base_url or None,
                    attacks=cfg.probes or None,   # probes carries the attack selection
                    objective=cfg.objective or None,
                    target_model=cfg.target_model or None,
                    target_purpose=cfg.target_purpose or None,
                    api_key=cfg.api_key or None,
                    auth_header=cfg.auth_header or None,
                    auth_scheme=cfg.auth_scheme or None,
                ))
            except Exception as e:
                log.exception(f"pyrit failed on {t.url}: {e}")
                print(f"    [!] pyrit failed on {t.url}: {e}")
        return findings

    if cfg.tool == "giskard":
        from adapters.giskard import run as run_giskard
        out_base = Path("/app/ai_attack_surface_scan/output") / (cfg.run_id or "dev")
        findings = []
        for t in targets:
            gdir = out_base / "giskard" / _safe_slug(f"{t.baseurl}{t.path}")
            try:
                findings.extend(run_giskard(
                    t, cfg.bounds, str(gdir), cfg.run_id,
                    judge_base_url=cfg.judge_base_url or None,
                    detectors=cfg.probes or None,   # probes carries the detector selection
                    target_model=cfg.target_model or None,
                    target_purpose=cfg.target_purpose or None,
                    api_key=cfg.api_key or None,
                    auth_header=cfg.auth_header or None,
                    auth_scheme=cfg.auth_scheme or None,
                ))
            except Exception as e:
                log.exception(f"giskard failed on {t.url}: {e}")
                print(f"    [!] giskard failed on {t.url}: {e}")
        return findings

    if cfg.tool == "promptfoo":
        from adapters.promptfoo import run as run_promptfoo
        out_base = Path("/app/ai_attack_surface_scan/output") / (cfg.run_id or "dev")
        findings = []
        for t in targets:
            pdir = out_base / "promptfoo" / _safe_slug(f"{t.baseurl}{t.path}")
            try:
                findings.extend(run_promptfoo(
                    t, cfg.bounds, str(pdir), cfg.run_id,
                    judge_base_url=cfg.judge_base_url or None,
                    plugins=cfg.probes or None,   # probes carries the plugin/chip selection
                    strategies=cfg.strategies or None,
                    target_model=cfg.target_model or None,
                    target_purpose=cfg.target_purpose or None,
                    api_key=cfg.api_key or None,
                    auth_header=cfg.auth_header or None,
                    auth_scheme=cfg.auth_scheme or None,
                ))
            except Exception as e:
                log.exception(f"promptfoo failed on {t.url}: {e}")
                print(f"    [!] promptfoo failed on {t.url}: {e}")
        return findings

    # Default: the Step-2 skeleton (no tool) — one dummy finding per target.
    return [make_dummy_finding(t, cfg.tool, cfg.run_id) for t in targets]


def run() -> int:
    cfg = load_config()
    print("=" * 64)
    print(f"[*] AI Attack Surface scan — tool={cfg.tool} run_id={cfg.run_id or 'dev'}")
    print(f"[*] project={cfg.project_id} user={cfg.user_id}")
    print("=" * 64)

    if not cfg.project_id or not cfg.user_id:
        print("[!] ERROR: PROJECT_ID and USER_ID are required")
        return 1

    # [Phase 1] Safety / bounds — fail fast before touching the graph or target.
    print("[Phase 1] Safety / bounds")
    try:
        enforce(cfg)
    except SafetyError as e:
        print(f"[!] Safety check failed: {e}")
        return 1

    driver = make_driver()
    try:
        if not verify_connection(driver):
            print("[!] ERROR: Neo4j connection failed")
            return 1

        with driver.session() as session:
            # [Phase 2] Target loading
            print("[Phase 2] Target loading")
            try:
                scope = ip_mode_scope(session, cfg)
            except ScopeRefused as e:
                print(f"[!] Scope refused: {e} -- nothing is attacked")
                return 1
            targets = load_targets(
                session,
                user_id=cfg.user_id,
                project_id=cfg.project_id,
                selected=cfg.targets or None,
                scope=scope,
            )
            print(f"    [+] {len(targets)} target(s) selected")
            if not targets:
                print("[!] No AI targets found/selected — nothing to do")
                return 0

            # [Phase 3] Attack
            print(f"[Phase 3] Attack (tool={cfg.tool})")
            if cfg.dry_run:
                print("    [+] dry-run: no payloads will be sent; not persisting")
                return 0
            findings = run_tool(cfg, targets)
            print(f"    [+] {len(findings)} finding(s) from {cfg.tool}")

            # [Phase 4] Findings -> graph
            print("[Phase 4] Findings")
            # Index targets by (baseurl, path) so a finding can hand its Target
            # (method + AI annotations) to the normalizer when it materialises a
            # custom target node.
            target_index = {}
            for t in targets:
                target_index.setdefault(
                    ((t.baseurl or "").rstrip("/"), t.path or "/"), t)
            existing = created = 0
            for f in findings:
                t = target_index.get(((f.baseurl or "").rstrip("/"), f.path or "/"))
                status = write_finding(session, f, cfg.user_id, cfg.project_id, target=t)
                if status == "existing":
                    existing += 1
                elif status == "created":
                    created += 1
            print(f"    [+] wrote {len(findings)} Vulnerability finding(s); "
                  f"{existing} linked to an existing Endpoint, "
                  f"{created} materialised a target node (all connected)")

        print("=" * 64)
        print(f"[*] Done. {len(targets)} target(s), {len(findings)} finding(s).")
        print("=" * 64)
        return 0
    finally:
        driver.close()


def main() -> int:
    try:
        return run()
    except Exception as e:  # never crash silently; surface to the orchestrator logs
        log.exception("AI Attack Surface scan crashed")
        print(f"[!] Unexpected error: {e}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
