"""P0-3 — /text-to-cypher must be auth-gated and must not echo detail.

The endpoint was unauthenticated while spending the BODY-NAMED user's LLM
provider key, and one request can cost up to 9 provider calls (3 attempts, each
wrapped in retry_llm_call). With the agent port on 0.0.0.0 in the base compose,
anyone on the LAN could burn any user's budget without logging in.

`require_internal_auth` is the right dependency rather than the auth-only one:
this is a BILLED endpoint, so it needs the token bucket and the daily spend cap,
not just a key check.

Runs inside the agent container (imports the FastAPI app + its deps).
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import api  # noqa: E402


def _dep_names(route):
    names = []
    for d in list(getattr(route, "dependencies", []) or []):
        call = getattr(d, "dependency", None)
        names.append(getattr(call, "__name__", str(call)))
    return names


def _route(path, method="POST"):
    for r in api.app.routes:
        if getattr(r, "path", "") == path and method in (getattr(r, "methods", set()) or set()):
            return r
    return None


class TextToCypherAuthTests(unittest.TestCase):
    def test_endpoint_is_registered(self):
        self.assertIsNotNone(_route("/text-to-cypher"), "/text-to-cypher route missing")

    def test_requires_billed_internal_auth(self):
        # RBAC 1.15 (NF-01): the master key or a graph run credential, never the
        # bare scanner key; still billed (token bucket + daily spend cap).
        deps = _dep_names(_route("/text-to-cypher"))
        self.assertIn(
            "require_master_or_run_credential_graph_billed",
            deps,
            f"/text-to-cypher is not gated by the BILLED dependency (deps: {deps})",
        )
        self.assertNotIn("require_internal_auth", deps)

    def test_not_merely_auth_only(self):
        # require_internal_auth_only skips the token bucket and the daily spend
        # cap, which is exactly what this endpoint needs.
        deps = _dep_names(_route("/text-to-cypher"))
        self.assertNotIn("require_internal_auth_only", deps)

    def test_unauthenticated_call_is_rejected_before_the_handler_runs(self):
        import os
        from unittest import mock

        from fastapi.testclient import TestClient

        with mock.patch.dict(os.environ, {"INTERNAL_API_KEY": "s3cret"}, clear=False):
            os.environ.pop("SCANNER_API_KEY", None)
            client = TestClient(api.app)
            resp = client.post(
                "/text-to-cypher",
                json={"question": "list ips", "user_id": "u1", "project_id": "p1"},
            )
        self.assertEqual(resp.status_code, 401)


class TextToCypherErrorNormalisationTests(unittest.TestCase):
    """A stable safe string leaves the process; detail goes to the server log.

    Every caller-visible message on this path is the second argument of a
    `_CypherSetupError(...)`, so that is where the assertion lives. A raised
    error must carry a LITERAL string: a provider message, a Neo4j error or a
    generated Cypher fragment must never travel out through one.
    """

    # Names holding an upstream message, a Neo4j error or a Cypher fragment.
    BANNED = {"e", "err", "last_error", "last_cypher", "cypher", "filtered"}

    def _raised_messages(self):
        """The message argument of every `_CypherSetupError(...)` construction."""
        import ast
        import inspect
        import textwrap

        for fn in (
            api.text_to_cypher,
            api._build_cypher_manager,
            api._generate_validated_cypher,
            api._cypher_model_error,
        ):
            tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                name = getattr(node.func, "id", None) or getattr(node.func, "attr", None)
                if name != "_CypherSetupError":
                    continue
                # _CypherSetupError(status, message)
                if len(node.args) >= 2:
                    yield fn.__name__, node.args[1]

    def test_no_raised_error_message_carries_exception_detail(self):
        import ast

        raised = list(self._raised_messages())
        self.assertTrue(raised, "no _CypherSetupError raises found - did the path move?")

        for fn_name, msg in raised:
            for sub in ast.walk(msg):
                if isinstance(sub, ast.Name) and sub.id in self.BANNED:
                    self.fail(
                        f"{fn_name} puts '{sub.id}' in a caller-visible message; "
                        "log the detail and raise a stable safe string instead"
                    )
                if isinstance(sub, ast.Call) and getattr(sub.func, "id", None) == "str":
                    self.fail(f"{fn_name} stringifies a value into a caller-visible message")

    def test_the_endpoint_returns_only_the_normalised_message(self):
        import inspect

        src = inspect.getsource(api.text_to_cypher)
        # The extra fields are built by _cypher_model_error from a class name and
        # an integer status only; ModelFailureTests pins that no text leaks.
        self.assertIn('content={"error": e.message, **e.fields}', src)
        # ...and nothing else builds an error body in the handler.
        self.assertEqual(src.count('"error"'), 1)


LEAK = "sk-live-LEAKED-FRAGMENT"


class _Status(Exception):
    def __init__(self, status):
        super().__init__(f"provider said no to key {LEAK}")
        self.status_code = status


class _Manager:
    """Counts generation calls; `_generate_cypher` raises what it is given."""

    def __init__(self, error):
        self.error = error
        self.calls = 0

    async def _generate_cypher(self, *_a, **_kw):
        self.calls += 1
        raise self.error


class ModelFailureTests(unittest.IsolatedAsyncioTestCase):
    """G-14: a failed model call is the model's problem, not a bad question."""

    async def _generate(self, error):
        manager = _Manager(error)
        with self.assertRaises(api._CypherSetupError) as raised:
            await api._generate_validated_cypher(manager, "q", "u1", "p1", True)
        return manager, raised.exception

    async def test_a_refused_key_is_model_unavailable_and_not_retried(self):
        manager, err = await self._generate(_Status(401))
        self.assertEqual(manager.calls, 1)
        self.assertEqual(err.status, 503)
        self.assertEqual(err.fields, {"code": "model_unavailable",
                                      "error_class": "_Status", "provider_status": 401})
        self.assertNotIn("rephras", err.message.lower())

    async def test_a_rate_limit_is_a_failed_call_with_its_status(self):
        manager, err = await self._generate(_Status(429))
        self.assertEqual(manager.calls, 1)
        self.assertEqual(err.status, 502)
        self.assertEqual(err.fields["code"], "model_call_failed")
        self.assertEqual(err.fields["provider_status"], 429)

    async def test_no_provider_text_reaches_the_answer(self):
        _, err = await self._generate(_Status(401))
        self.assertNotIn(LEAK, err.message)
        self.assertNotIn(LEAK, repr(err.fields))

    async def test_the_endpoint_answers_the_fields(self):
        async def build(*_a):
            return _Manager(_Status(429))

        from unittest import mock
        with mock.patch.object(api, "_build_cypher_manager", build):
            resp = await api.text_to_cypher(api.TextToCypherRequest(
                question="q", user_id="u1", project_id="p1"))
        import json
        body = json.loads(resp.body)
        self.assertEqual(resp.status_code, 502)
        self.assertEqual(body["code"], "model_call_failed")
        self.assertEqual(body["provider_status"], 429)
        self.assertNotIn(LEAK, resp.body.decode())


if __name__ == "__main__":
    unittest.main()
