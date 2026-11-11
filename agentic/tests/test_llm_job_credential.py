"""
The scan containers' agent routes (/llm/*, /jev/*) take the user from the scan's job
credential (step 1.16, HD-21 LLM part, NF-01).

A scan calls them with the scanner key and X-Redamon-Job, the credential the webapp
minted for its start. The route acts for the credential's tenant and project: a body
user_id or project_id naming anyone else is refused, one left out is filled from the
credential, and the LLM limits count against the tenant. The bare scanner key opens
nothing; the master key (the webapp) keeps the body's ids.
"""
import os
import sys
import time
import unittest
from contextlib import asynccontextmanager
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

MASTER = "master-key-for-llm-job-tests"
SCANNER = "scanner-key-for-llm-job-tests"
KEYS = {"INTERNAL_API_KEY": MASTER, "SCANNER_API_KEY": SCANNER}

with patch.dict(os.environ, KEYS):
    @asynccontextmanager
    async def _no_lifespan(_app):
        yield

    with patch("api.lifespan", _no_lifespan):
        import api  # noqa: E402
import llm_guard  # noqa: E402
import machine_credential as mc  # noqa: E402
from fastapi.routing import APIRoute  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

LLM_BODIES = {
    "/llm/ffuf-extensions": {"url": "http://t.example.test/", "headers": {}, "model": "gpt-4o"},
    "/llm/nuclei-tags": {"technologies": ["php"], "servers": [], "current_tags": ["cve"],
                         "candidates": ["cve", "php"], "model": "gpt-4o"},
    "/llm/waf-classify": {"url": "http://t.example.test/", "status_code": 403, "headers": {}, "model": "gpt-4o"},
    "/llm/nuclei-fp-filter": {"template_id": "t-1", "model": "gpt-4o"},
    "/llm/takeover-classify": {"hostname": "h.example.test", "model": "gpt-4o"},
}
JEV_BODIES = {
    "/jev/ffuf-extensions": LLM_BODIES["/llm/ffuf-extensions"],
    "/jev/nuclei-tags": LLM_BODIES["/llm/nuclei-tags"],
    "/jev/waf-classify": LLM_BODIES["/llm/waf-classify"],
    "/jev/takeover-classify": LLM_BODIES["/llm/takeover-classify"],
    "/jev/ffuf-base-paths": {"candidates": ["admin"], "cap": 1},
    "/jev/page-type": {"pages": [{"url": "http://t.example.test/"}]},
    "/jev/tool-health": {"tool": "katana", "return_code": 1, "elapsed_s": 1.0, "seed_count": 1, "stderr": "x"},
    "/jev/crawl-seed-order": {"hosts": [{"hostname": "t.example.test"}]},
    "/jev/serialized-classify": {"blobs": [{"snippet": "rO0ABX"}]},
    "/jev/route-privacy-rank": {"routes": [{"path": "/a"}]},
    "/jev/route-exposure-assess": {"candidates": [{"path": "/a"}]},
}
SCAN_ROUTES = {**LLM_BODIES, **JEV_BODIES}


def _job(tenant="owner-1", project="proj-1", exp_in=3600, master=MASTER, label=mc.JOB_CREDENTIAL_LABEL,
         **extra) -> str:
    claims = {"aud": "scan", "ten": tenant, "pid": project, "job": "job-1", "exp": int(time.time()) + exp_in, **extra}
    return mc.mint(claims, mc.derive_key(master, label))


class _StubLLM:
    async def ainvoke(self, _messages):
        return type("R", (), {"content": "{}"})()


class _Base(unittest.TestCase):
    def setUp(self):
        env = patch.dict(os.environ, KEYS)
        env.start()
        self.addCleanup(env.stop)
        llm_guard.reset_state()
        self.client = TestClient(api.app)
        self.built_for = []
        self.jev_for = []

        def _build(model, user_id):
            self.built_for.append(user_id)
            return _StubLLM()

        async def _run_jev(endpoint, user_id, project_id, n, coro):
            self.jev_for.append((user_id, project_id))
            return {"ok": True}

        for target, fake in (("_build_llm_with_model_for_user", _build), ("_run_jev", _run_jev)):
            p = patch.object(api, target, side_effect=fake)
            p.start()
            self.addCleanup(p.stop)

    def post(self, path, body, *, key=SCANNER, job=None):
        headers = {"x-internal-key": key} if key else {}
        if job:
            headers["x-redamon-job"] = job
        return self.client.post(path, json=body, headers=headers)

    def acted_for(self, path):
        return self.built_for[-1] if path.startswith("/llm/") else self.jev_for[-1][0]


class GatesDeclared(_Base):
    def test_every_scan_route_takes_the_job_gate_and_not_the_bare_key_gate(self):
        seen = set()
        for r in api.app.routes:
            if isinstance(r, APIRoute) and r.path.startswith(("/llm/", "/jev/")):
                calls = [d.call for d in r.dependant.dependencies]
                self.assertIn(llm_guard.require_master_or_job_credential, calls, r.path)
                self.assertNotIn(llm_guard.require_internal_auth, calls, r.path)
                seen.add(r.path)
        self.assertEqual(seen, set(SCAN_ROUTES))


class ScannerKeyNeedsACredential(_Base):
    def test_scanner_key_needs_a_credential(self):
        with self.assertLogs("llm_guard", level="WARNING") as logs:
            for path, body in SCAN_ROUTES.items():
                with self.subTest(path=path):
                    r = self.post(path, {**body, "user_id": "owner-1", "project_id": "proj-1"})
                    self.assertEqual(r.status_code, 401, r.text)
                    self.assertEqual(r.json()["detail"]["code"], "job_credential_missing")
        self.assertIn("[rbac] job credential refused reason=missing", "\n".join(logs.output))
        self.assertEqual(self.built_for + self.jev_for, [])

    def test_a_bad_credential_is_refused(self):
        cases = {
            "expired": _job(exp_in=-1),
            "bad_signature": _job(master="another-master"),
            "malformed": "not-a-credential",
            # A run credential is signed under another label: never a job credential.
            "run credential": mc.mint({"aud": "scan", "ten": "owner-1", "pid": "proj-1", "run": "r",
                                       "exp": int(time.time()) + 60},
                                      mc.derive_key(MASTER, mc.RUN_CREDENTIAL_LABEL)),
        }
        for name, token in cases.items():
            with self.subTest(case=name):
                r = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"], job=token)
                self.assertEqual(r.status_code, 401, r.text)
                self.assertTrue(r.json()["detail"]["code"].startswith("job_credential_"))
        self.assertEqual(self.built_for, [])

    def test_a_credential_without_the_scanner_key_opens_nothing(self):
        r = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"], key=None, job=_job())
        self.assertEqual(r.status_code, 401)
        r = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"], key="wrong-key", job=_job())
        self.assertEqual(r.status_code, 401)
        self.assertEqual(self.built_for, [])


class UserFromTheCredential(_Base):
    def test_user_from_the_credential(self):
        for path, body in SCAN_ROUTES.items():
            with self.subTest(path=path):
                r = self.post(path, body, job=_job())
                # 502: the stub model's "{}" fails some routes' answer schema, after the gate.
                self.assertIn(r.status_code, (200, 502), r.text)
                self.assertEqual(self.acted_for(path), "owner-1")
        self.assertEqual({p for _, p in self.jev_for}, {"proj-1"})

    def test_a_matching_body_user_is_accepted(self):
        r = self.post("/jev/nuclei-tags", {**JEV_BODIES["/jev/nuclei-tags"], "user_id": "owner-1",
                                           "project_id": "proj-1"}, job=_job())
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.jev_for, [("owner-1", "proj-1")])

    def test_mismatched_body_user_refused(self):
        for path, body in SCAN_ROUTES.items():
            for field, code in (("user_id", "job_credential_user_mismatch"),
                                ("project_id", "job_credential_project_mismatch")):
                with self.subTest(path=path, field=field):
                    r = self.post(path, {**body, field: "someone-else"}, job=_job())
                    self.assertEqual(r.status_code, 403, r.text)
                    self.assertEqual(r.json()["detail"]["code"], code)
        self.assertEqual(self.built_for + self.jev_for, [])

    def test_the_limits_count_against_the_credentials_tenant(self):
        with patch.object(llm_guard, "_daily_cap", llm_guard._DailyCap(1)):
            first = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"], job=_job())
            second = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"], job=_job())
            other = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"],
                              job=_job(tenant="owner-2", project="proj-2"))
        self.assertIn(first.status_code, (200, 502))
        self.assertEqual(second.status_code, 429)
        self.assertIn(other.status_code, (200, 502))


class MasterKeyUnchanged(_Base):
    def test_the_master_key_keeps_the_body_ids(self):
        r = self.post("/llm/nuclei-tags", {**LLM_BODIES["/llm/nuclei-tags"], "user_id": "u-body"}, key=MASTER)
        self.assertIn(r.status_code, (200, 502), r.text)
        self.assertEqual(self.built_for, ["u-body"])
        r = self.post("/jev/page-type", {**JEV_BODIES["/jev/page-type"], "user_id": "u-body", "project_id": "p-body"},
                      key=MASTER)
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(self.jev_for, [("u-body", "p-body")])

    def test_without_a_configured_master_key_the_routes_are_closed(self):
        for weak in ("", "changeme"):
            with self.subTest(master=weak or "<unset>"), patch.dict(os.environ, {"INTERNAL_API_KEY": weak}):
                r = self.post("/llm/nuclei-tags", LLM_BODIES["/llm/nuclei-tags"], job=_job())
                self.assertEqual(r.status_code, 503)


if __name__ == "__main__":
    unittest.main(verbosity=2)
