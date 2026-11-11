"""
Machine credentials across runtimes (T15, step 1.16): a job credential the webapp's
TypeScript minter produces must verify in the agent and in the orchestrator.

The shared vectors (tests/fixtures/machine_credential/vectors.json) carry the tokens;
webapp/src/lib/authz/machineCredential.test.ts asserts the TypeScript minter produces
each one byte for byte, so a token that verifies here is a TypeScript-minted token
verifying in Python. Both Python verifiers run side by side (this section's PYTHONPATH
holds recon_orchestrator/), so neither can drift from the other or from the webapp.
"""
import json
import os
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

_AGENTIC = Path(__file__).resolve().parents[1]
_REPO = _AGENTIC.parent
for _p in (str(_AGENTIC), str(_REPO / "recon_orchestrator")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import job_credential as orch  # noqa: E402
import machine_credential as mc  # noqa: E402

VECTORS = json.loads((_REPO / "tests" / "fixtures" / "machine_credential" / "vectors.json").read_text())
MASTER = VECTORS["master"]
NOW = 1_800_000_000
JOBS = [v for v in VECTORS["vectors"] if v["label"] == "job"]
RUNS = [v for v in VECTORS["vectors"] if v["label"] == "run"]


class TypeScriptJobCredentialVerifiesInPython(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, {"INTERNAL_API_KEY": MASTER})
        env.start()
        self.addCleanup(env.stop)

    def test_the_derived_keys_match_the_webapp(self):
        self.assertEqual(mc.derive_key(MASTER, mc.JOB_CREDENTIAL_LABEL).hex(), VECTORS["job_key_hex"])
        self.assertEqual(mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL).hex(), VECTORS["run_key_hex"])

    def test_typescript_job_credential_verifies_in_python(self):
        self.assertGreaterEqual(len(JOBS), 3)
        for v in JOBS:
            with self.subTest(vector=v["name"]):
                self.assertEqual(mc.verify_job_credential(v["token"], now=NOW), v["claims"])
                self.assertEqual(orch.verify_job_credential(v["token"], v["claims"]["pid"], now=NOW), v["claims"])

    def test_python_mints_the_same_bytes(self):
        for v in VECTORS["vectors"]:
            label = mc.JOB_CREDENTIAL_LABEL if v["label"] == "job" else mc.RUN_CREDENTIAL_LABEL
            with self.subTest(vector=v["name"]):
                self.assertEqual(mc.mint(v["claims"], mc.derive_key(MASTER, label)), v["token"])

    def test_a_job_credential_is_not_a_run_credential_nor_the_other_way_round(self):
        for v in JOBS:
            with self.subTest(vector=v["name"]):
                with self.assertRaises(mc.CredentialRefused) as ctx:
                    mc.verify_run_credential(v["token"], "graph", now=NOW)
                self.assertEqual(ctx.exception.code, "bad_signature")
        for v in RUNS:
            with self.subTest(vector=v["name"]):
                with self.assertRaises(mc.CredentialRefused):
                    mc.verify_job_credential(v["token"], now=NOW)
                with self.assertRaises(orch.JobCredentialRefused):
                    orch.verify_job_credential(v["token"], v["claims"]["pid"], now=NOW)

    def test_both_python_verifiers_refuse_alike(self):
        key = mc.derive_key(MASTER, mc.JOB_CREDENTIAL_LABEL)
        good = {"aud": "scan", "ten": "u1", "pid": "p1", "job": "j1", "exp": NOW + 60}
        body, sig = mc.mint(good, key).split(".")
        cases = {
            "expired": (mc.mint(good, key), NOW + 60),
            "wrong_audience": (mc.mint({**good, "aud": "graph"}, key), NOW),
            "bad_signature": (f"{mc.mint({**good, 'ten': 'u2'}, key).split('.')[0]}.{sig}", NOW),
            "malformed": ("not-a-token", NOW),
            "missing_claims": (mc.mint({**good, "job": None, "run": "r"}, key), NOW),
            "other master": (mc.mint(good, mc.derive_key("another-master", mc.JOB_CREDENTIAL_LABEL)), NOW),
        }
        for name, (token, now) in cases.items():
            with self.subTest(case=name):
                with self.assertRaises(mc.CredentialRefused) as agent:
                    mc.verify_job_credential(token, now=now)
                with self.assertRaises(orch.JobCredentialRefused) as orchestrator:
                    orch.verify_job_credential(token, "p1", now=now)
                self.assertEqual(agent.exception.code, orchestrator.exception.code)

    def test_a_weak_master_key_verifies_nothing(self):
        token = JOBS[0]["token"]
        for weak in ("", "changeme"):
            with self.subTest(master=weak or "<unset>"), patch.dict(os.environ, {"INTERNAL_API_KEY": weak}):
                with self.assertRaises(mc.CredentialRefused) as agent:
                    mc.verify_job_credential(token, now=NOW)
                self.assertEqual(agent.exception.code, "weak_master_key")
                with self.assertRaises(orch.JobCredentialRefused) as orchestrator:
                    orch.verify_job_credential(token, JOBS[0]["claims"]["pid"], now=NOW)
                self.assertEqual(orchestrator.exception.code, "weak_master_key")


if __name__ == "__main__":
    unittest.main(verbosity=2)
