"""
Verifies the orchestrator spawns the capture-proxy + ingest with the CORRECT env
after the DB-source-of-truth refactor, without spawning real containers (docker's
containers.run is intercepted).

Post-refactor contract:
  - The egress-guard toggles and body-storage policy are NO LONGER proxy env: they
    are the DB single-source-of-truth, materialised to /spool/.capture-config.json by
    the orchestrator reconciler and hot-reloaded by the proxy. So the proxy env must
    carry ONLY structural vars + the always-on service-IP denylist.
  - The listen port (proxy command) and redact-secrets (ingest env) remain spawn-baked.

Run: python3 -m unittest tests.test_capture_proxy_env   (from /app in the
recon-orchestrator container, which has `docker`).
"""
from __future__ import annotations

import asyncio
import sys
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

import container_manager as cm  # noqa: E402

# Env keys that MUST NOT appear on the proxy container any more — they moved to the
# DB-materialised config file and are hot-reloaded.
_MOVED_TO_FILE = [
    "CAPTURE_PROXY_MAX_BODY_KB", "CAPTURE_PROXY_STORE_BODIES", "CAPTURE_STORE_REQ_BODIES",
    "CAPTURE_STORE_RESP_BODIES", "CAPTURE_MAX_STORE_MB", "CAPTURE_BODY_RULES",
    "CAPTURE_EGRESS_BLOCK_EMPTY_HOST", "CAPTURE_EGRESS_BLOCK_HARD_GUARDRAIL",
    "CAPTURE_EGRESS_FAIL_CLOSED", "CAPTURE_EGRESS_BLOCK_UNRESOLVABLE",
    "CAPTURE_EGRESS_BLOCK_PRIVATE", "CAPTURE_EGRESS_BLOCK_LOOPBACK",
    "CAPTURE_EGRESS_BLOCK_LINK_LOCAL", "CAPTURE_EGRESS_BLOCK_CGNAT",
    "CAPTURE_EGRESS_BLOCK_RESERVED", "CAPTURE_EGRESS_BLOCK_MULTICAST",
    "CAPTURE_EGRESS_BLOCK_UNSPECIFIED",
]


def _spawn(config: dict):
    """Run start_capture_proxy with docker intercepted; return (proxy_kw, ingest_kw)."""
    mgr = cm.ContainerManager.__new__(cm.ContainerManager)  # skip docker.from_env
    calls = []

    class _Containers:
        def run(self, image, **kw):
            calls.append(kw)
            return mock.Mock()

    mgr.client = mock.Mock()
    mgr.client.containers = _Containers()
    mgr._remove_container_if_exists = lambda name: None
    mgr._capture_image = lambda: "redamon-capture-proxy:latest"
    mgr._capture_port = lambda: 8888

    async def _fake_status():
        return {"running": True}
    mgr.capture_proxy_status = _fake_status

    asyncio.run(mgr.start_capture_proxy(config))
    # calls[0] = proxy, calls[1] = ingest (spawn order in start_capture_proxy).
    return calls[0], calls[1]


class TestCaptureProxyEnvMapping(unittest.TestCase):
    def test_proxy_env_is_minimal_structural_only(self):
        proxy, _ = _spawn({})
        env = proxy["environment"]
        # ONLY structural + the security-invariant denylist survive on the proxy.
        self.assertEqual(
            set(env.keys()),
            {"CAPTURE_SPOOL_DIR", "CAPTURE_BODIES_DIR", "CAPTURE_BLOCKED_IPS"},
            f"unexpected proxy env keys: {sorted(env.keys())}",
        )
        self.assertEqual(env["CAPTURE_SPOOL_DIR"], "/spool")
        self.assertEqual(env["CAPTURE_BODIES_DIR"], "/bodies")

    def test_egress_and_body_knobs_never_on_proxy_env(self):
        # Even when the UI/config supplies these, they must NOT be injected as env
        # (they are DB-sourced + hot-reloaded via the file now).
        proxy, _ = _spawn({
            "maxBodyKb": 128, "storeBodies": False, "storeReqBodies": False,
            "maxStoreMb": 0, "bodyRules": {"image": "disk"},
            "egressBlockPrivate": False, "egressBlockLoopback": False,
        })
        env = proxy["environment"]
        for k in _MOVED_TO_FILE:
            self.assertNotIn(k, env, f"{k} leaked back onto the proxy env")

    def test_blocked_ips_is_still_proxy_env_and_overridable(self):
        # Security invariant: the service-IP denylist stays on the proxy env. The
        # per-user Kali sandbox pool follows the operator's entries (TD-24): the
        # proxy sits on every sandbox network and must never carry one to another.
        proxy, _ = _spawn({"blockedIps": "10.9.9.9,172.31.0.1"})
        self.assertEqual(proxy["environment"]["CAPTURE_BLOCKED_IPS"],
                         "10.9.9.9,172.31.0.1,10.214.0.0/16")

    def test_port_is_baked_into_proxy_command_not_env(self):
        proxy, _ = _spawn({"port": 9999})
        # The listen port is a spawn-baked knob -> it is in the mitmdump command.
        self.assertIn("--listen-port", proxy["command"])
        i = proxy["command"].index("--listen-port")
        self.assertEqual(proxy["command"][i + 1], "9999")

    def test_redact_secrets_maps_to_ingest_env(self):
        # redact is consumed by the INGEST container, not the proxy -> still spawn env.
        _, ingest = _spawn({"redactSecrets": False})
        self.assertEqual(ingest["environment"]["CAPTURE_PROXY_REDACT_SECRETS"], "false")
        _, ingest2 = _spawn({"redactSecrets": True})
        self.assertEqual(ingest2["environment"]["CAPTURE_PROXY_REDACT_SECRETS"], "true")

    def test_proxy_still_locked_down(self):
        # Regression: the hardening flags must not have been lost in the refactor.
        proxy, _ = _spawn({})
        self.assertEqual(proxy["cap_drop"], ["ALL"])
        self.assertTrue(proxy["read_only"])
        # It joins every per-user Kali sandbox network: no forwarding between them (TD-23).
        self.assertEqual(proxy["sysctls"], {"net.ipv4.ip_forward": "0"})


if __name__ == "__main__":
    unittest.main()
