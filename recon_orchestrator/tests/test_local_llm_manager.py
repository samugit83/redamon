"""
Unit + regression tests for the on-demand local LLM (Ollama) lifecycle manager.

Stdlib `unittest` + `unittest.mock` only (pytest/httpx are not in the
recon-orchestrator image). Docker and the Ollama HTTP API are fully mocked, so
these run with no daemon and no network:

    docker compose exec -T recon-orchestrator python -m unittest \
        tests.test_local_llm_manager -v

Coverage map:
  - lease/ref-counting (the "N tools share one judge" guarantee)
  - container bring-up: fresh / already-running / stale-restart
  - image pull only when missing
  - model presence matching (incl. the llama3 vs llama3.1 regression)
  - model pull: streamed NDJSON drain, error line, exception
  - readiness poll: success / timeout
  - failure-soft: docker errors never propagate
  - teardown: only at lease 0, volume never touched, idempotent
  - concurrency regression: no duplicate containers.run() under parallel ensure
  - networking regression: bridge network + published port, never host network
"""
import io
import sys
import threading
import unittest
from unittest.mock import MagicMock, patch

from docker.errors import APIError, ImageNotFound, NotFound

import local_llm_manager as llm
from local_llm_manager import LocalLlmManager, LocalLlmStatus, _model_matches


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def make_manager(client=None):
    """A manager with a mocked docker client (no daemon)."""
    client = client or MagicMock()
    return LocalLlmManager(client=client)


def fake_container(status="running", cid="deadbeefcafe0000"):
    c = MagicMock()
    c.status = status
    c.id = cid
    return c


class _FakeHTTPResponse(io.BytesIO):
    """Minimal context-manager HTTP response for urlopen mocks."""
    def __init__(self, body=b"", status=200, lines=None):
        super().__init__(body)
        self.status = status
        self._lines = lines

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False

    def __iter__(self):
        # /api/pull streaming: iterate NDJSON lines
        if self._lines is not None:
            return iter(self._lines)
        return super().__iter__()


# --------------------------------------------------------------------------- #
# _model_matches (Bug B regression)
# --------------------------------------------------------------------------- #

class TestModelMatches(unittest.TestCase):
    def test_exact_match(self):
        self.assertTrue(_model_matches(["qwen2.5:7b"], "qwen2.5:7b"))

    def test_other_tag_same_name_matches(self):
        # Any tag of the same model name counts as present.
        self.assertTrue(_model_matches(["qwen2.5:0.5b"], "qwen2.5:7b"))

    def test_absent(self):
        self.assertFalse(_model_matches(["mistral:7b"], "qwen2.5:7b"))

    def test_empty(self):
        self.assertFalse(_model_matches([], "qwen2.5:7b"))

    def test_llama3_does_not_match_llama31(self):
        # Regression: prefix matching used to report llama3 present when only
        # llama3.1 was pulled. Name-segment compare must reject this.
        self.assertFalse(_model_matches(["llama3.1:8b"], "llama3"))

    def test_llama31_exact_family(self):
        self.assertTrue(_model_matches(["llama3.1:8b"], "llama3.1:70b"))


# --------------------------------------------------------------------------- #
# Lease / ref-counting
# --------------------------------------------------------------------------- #

class TestRefCounting(unittest.TestCase):
    def setUp(self):
        self.mgr = make_manager()
        # Make bring-up + readiness + model all succeed cheaply.
        self.mgr._ensure_container = MagicMock()
        self.mgr._wait_ready = MagicMock(return_value=True)
        self.mgr._ensure_model = MagicMock(return_value=True)
        self.mgr._list_models = MagicMock(return_value=["qwen2.5:7b"])
        self.mgr._container_id = MagicMock(return_value="cid")

    def test_ensure_increments_lease(self):
        s = self.mgr.ensure_up("qwen2.5:7b")
        self.assertEqual(s.leases, 1)
        self.assertTrue(s.available)

    def test_two_ensures_two_leases_one_container(self):
        self.mgr.ensure_up("m")
        self.mgr.ensure_up("m")
        self.assertEqual(self.mgr._leases, 2)
        # bring-up is idempotent: _ensure_container called each time but it is a
        # no-op when already running (mocked); the point is no exception/leak.
        self.assertEqual(self.mgr._ensure_container.call_count, 2)

    def test_release_keeps_container_until_zero(self):
        self.mgr.ensure_up("m")
        self.mgr.ensure_up("m")
        # First release: still 1 lease -> container kept, no teardown.
        self.mgr._is_running = MagicMock(return_value=True)
        s1 = self.mgr.release()
        self.assertEqual(s1.leases, 1)
        self.mgr.client.containers.get.assert_not_called()
        # Second release: lease 0 -> teardown.
        self.mgr.client.containers.get.return_value = fake_container()
        s2 = self.mgr.release()
        self.assertEqual(s2.leases, 0)
        self.mgr.client.containers.get.assert_called_once_with(llm.LLM_CONTAINER_NAME)

    def test_release_below_zero_is_idempotent(self):
        self.mgr.client.containers.get.side_effect = NotFound("gone")
        s = self.mgr.release()
        self.assertEqual(s.leases, 0)
        # Another release stays at 0, never negative.
        s2 = self.mgr.release()
        self.assertEqual(s2.leases, 0)

    def test_ensure_then_release_returns_to_zero_on_success(self):
        self.mgr.ensure_up("m")
        self.mgr.client.containers.get.return_value = fake_container()
        self.mgr.release()
        self.assertEqual(self.mgr._leases, 0)


# --------------------------------------------------------------------------- #
# Container bring-up
# --------------------------------------------------------------------------- #

class TestContainerBringup(unittest.TestCase):
    def setUp(self):
        self.client = MagicMock()
        self.mgr = make_manager(self.client)

    def test_skips_run_when_already_running(self):
        self.client.containers.get.return_value = fake_container(status="running")
        self.mgr._ensure_container()
        self.client.containers.run.assert_not_called()

    def test_removes_stale_then_runs(self):
        self.client.containers.get.return_value = fake_container(status="exited")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        self.client.containers.run.assert_called_once()

    def test_runs_fresh_when_absent(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        self.client.containers.run.assert_called_once()

    def test_image_pulled_only_when_missing(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.side_effect = ImageNotFound("no image")
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        self.client.images.pull.assert_called_once_with(llm.LLM_IMAGE)

    def test_image_not_pulled_when_present(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        self.client.images.pull.assert_not_called()

    # --- networking regression (the host-network-vs-bridge bug) --- #
    def test_run_uses_bridge_network_and_published_port_not_host(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        kwargs = self.client.containers.run.call_args.kwargs
        # Regression: must NOT use host networking (orchestrator is on bridge).
        self.assertNotIn("network_mode", kwargs)
        self.assertEqual(kwargs["network"], llm.LLM_NETWORK)
        # Port must be published so host-network scan containers reach localhost.
        self.assertEqual(kwargs["ports"], {f"{llm.LLM_PORT}/tcp": ("127.0.0.1", llm.LLM_PORT)})

    def test_port_published_on_loopback_only(self):
        # T9/D29: Ollama's API has no auth; a bare port (or a 0.0.0.0 host)
        # publishes it on every host interface, past ufw, to the LAN or internet.
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        ports = self.client.containers.run.call_args.kwargs["ports"]
        self.assertEqual(len(ports), 1)
        for binding in ports.values():
            self.assertIsInstance(binding, tuple, "a bare host port binds every interface")
            self.assertEqual(binding[0], "127.0.0.1")
        self.assertEqual(llm.LLM_PUBLISH_HOST, "127.0.0.1")

    def test_ollama_listens_on_the_container_interface_for_the_port_forward(self):
        # OLLAMA_HOST=0.0.0.0 is the container's own interface, which Docker's
        # port forward needs (127.0.0.1 there would break it); exposure is
        # decided by the host-side binding above.
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        kwargs = self.client.containers.run.call_args.kwargs
        self.assertEqual(kwargs["environment"]["OLLAMA_HOST"], f"0.0.0.0:{llm.LLM_PORT}")

    def test_run_mounts_weights_volume_rw(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        self.mgr._ensure_container()
        kwargs = self.client.containers.run.call_args.kwargs
        self.assertEqual(
            kwargs["volumes"],
            {llm.LLM_MODELS_VOLUME: {"bind": "/root/.ollama", "mode": "rw"}},
        )

    def test_no_gpu_by_default(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        with patch.object(llm, "LLM_USE_GPU", False):
            self.mgr._ensure_container()
        self.assertNotIn("device_requests", self.client.containers.run.call_args.kwargs)

    def test_gpu_passthrough_when_enabled(self):
        self.client.containers.get.side_effect = NotFound("absent")
        self.client.images.get.return_value = MagicMock()
        self.client.containers.run.return_value = fake_container()
        with patch.object(llm, "LLM_USE_GPU", True):
            self.mgr._ensure_container()
        reqs = self.client.containers.run.call_args.kwargs.get("device_requests")
        self.assertTrue(reqs, "device_requests must be set when GPU enabled")


# --------------------------------------------------------------------------- #
# Ollama HTTP API (urllib mocked)
# --------------------------------------------------------------------------- #

class TestOllamaHttp(unittest.TestCase):
    def setUp(self):
        self.mgr = make_manager()

    def test_list_models_parses_tags(self):
        body = b'{"models":[{"name":"qwen2.5:7b"},{"name":"mistral:7b"}]}'
        with patch("urllib.request.urlopen", return_value=_FakeHTTPResponse(body)):
            self.assertEqual(self.mgr._list_models(), ["qwen2.5:7b", "mistral:7b"])

    def test_list_models_soft_fails_to_empty(self):
        with patch("urllib.request.urlopen", side_effect=OSError("refused")):
            self.assertEqual(self.mgr._list_models(), [])

    def test_wait_ready_true_on_200(self):
        with patch("urllib.request.urlopen", return_value=_FakeHTTPResponse(b"", status=200)):
            self.assertTrue(self.mgr._wait_ready(timeout_s=5))

    def test_wait_ready_times_out(self):
        # Always refuse; patch sleep + a monotonic clock that advances past the
        # deadline so the loop exits quickly.
        ticks = iter([0, 1, 2, 3, 4, 5, 6, 7, 8])
        with patch("urllib.request.urlopen", side_effect=OSError("refused")), \
             patch("local_llm_manager.time.sleep"), \
             patch("local_llm_manager.time.monotonic", side_effect=lambda: next(ticks)):
            self.assertFalse(self.mgr._wait_ready(timeout_s=3))

    def test_ensure_model_already_present_skips_pull(self):
        self.mgr._list_models = MagicMock(return_value=["qwen2.5:7b"])
        with patch("urllib.request.urlopen") as uo:
            self.assertTrue(self.mgr._ensure_model("qwen2.5:7b"))
            uo.assert_not_called()  # no /api/pull

    def test_ensure_model_pulls_then_confirms(self):
        # Absent first, present after pull.
        self.mgr._list_models = MagicMock(side_effect=[[], ["qwen2.5:7b"]])
        pull_resp = _FakeHTTPResponse(lines=[b'{"status":"pulling"}\n', b'{"status":"success"}\n'])
        with patch("urllib.request.urlopen", return_value=pull_resp):
            self.assertTrue(self.mgr._ensure_model("qwen2.5:7b"))

    def test_ensure_model_pull_error_line_returns_false(self):
        self.mgr._list_models = MagicMock(return_value=[])
        pull_resp = _FakeHTTPResponse(lines=[b'{"error":"no such model"}\n'])
        with patch("urllib.request.urlopen", return_value=pull_resp):
            self.assertFalse(self.mgr._ensure_model("bogus:1b"))

    def test_ensure_model_pull_exception_returns_false(self):
        self.mgr._list_models = MagicMock(return_value=[])
        with patch("urllib.request.urlopen", side_effect=OSError("network down")):
            self.assertFalse(self.mgr._ensure_model("qwen2.5:7b"))


# --------------------------------------------------------------------------- #
# Failure-soft contract
# --------------------------------------------------------------------------- #

class TestFailureSoft(unittest.TestCase):
    def setUp(self):
        self.mgr = make_manager()

    def test_ensure_up_never_raises_on_docker_error(self):
        self.mgr._ensure_container = MagicMock(side_effect=APIError("daemon boom"))
        self.mgr._is_running = MagicMock(return_value=False)
        self.mgr._container_id = MagicMock(return_value=None)
        s = self.mgr.ensure_up("m")
        self.assertIsInstance(s, LocalLlmStatus)
        self.assertFalse(s.available)
        self.assertIn("boom", s.warning)
        # Lease still held (caller must release) — contract is ensure/release paired.
        self.assertEqual(s.leases, 1)

    def test_ensure_up_not_ready_is_unavailable(self):
        self.mgr._ensure_container = MagicMock()
        self.mgr._wait_ready = MagicMock(return_value=False)
        self.mgr._is_running = MagicMock(return_value=True)
        self.mgr._container_id = MagicMock(return_value="cid")
        s = self.mgr.ensure_up("m")
        self.assertFalse(s.available)
        self.assertIn("did not become ready", s.warning)

    def test_ensure_up_model_pull_fail_running_but_unavailable(self):
        self.mgr._ensure_container = MagicMock()
        self.mgr._wait_ready = MagicMock(return_value=True)
        self.mgr._ensure_model = MagicMock(return_value=False)
        self.mgr._list_models = MagicMock(return_value=[])
        self.mgr._container_id = MagicMock(return_value="cid")
        s = self.mgr.ensure_up("m")
        self.assertTrue(s.running)
        self.assertFalse(s.available)
        self.assertIn("degrade to no-judge", s.warning)

    def test_teardown_failure_does_not_raise(self):
        c = fake_container()
        c.stop.side_effect = APIError("cannot stop")
        self.mgr.client.containers.get.return_value = c
        # Should swallow the error and still report leases 0.
        s = self.mgr.release()
        self.assertEqual(s.leases, 0)


# --------------------------------------------------------------------------- #
# status() — read-only
# --------------------------------------------------------------------------- #

class TestStatus(unittest.TestCase):
    def setUp(self):
        self.mgr = make_manager()

    def test_status_idle(self):
        self.mgr._is_running = MagicMock(return_value=False)
        s = self.mgr.status()
        self.assertFalse(s.running)
        self.assertFalse(s.available)
        self.assertEqual(s.leases, 0)
        self.assertEqual(s.models, [])

    def test_status_running_with_model(self):
        self.mgr._is_running = MagicMock(return_value=True)
        self.mgr._container_id = MagicMock(return_value="cid")
        self.mgr._list_models = MagicMock(return_value=[llm.LLM_MODEL])
        s = self.mgr.status()
        self.assertTrue(s.running)
        self.assertTrue(s.available)

    def test_status_does_not_change_leases(self):
        self.mgr._is_running = MagicMock(return_value=True)
        self.mgr._list_models = MagicMock(return_value=[])
        self.mgr._container_id = MagicMock(return_value="cid")
        before = self.mgr._leases
        self.mgr.status()
        self.assertEqual(self.mgr._leases, before)

    def test_status_dict_shape(self):
        self.mgr._is_running = MagicMock(return_value=False)
        d = self.mgr.status().to_dict()
        self.assertEqual(
            set(d.keys()),
            {"available", "running", "containerId", "baseUrl", "model",
             "modelPresent", "leases", "models", "warning"},
        )
        # Scan-facing URL is loopback (host-network scan containers reach it there).
        self.assertEqual(d["baseUrl"], llm.LLM_SCAN_URL)
        self.assertTrue(d["baseUrl"].startswith("http://localhost"))


# --------------------------------------------------------------------------- #
# shutdown()
# --------------------------------------------------------------------------- #

class TestShutdown(unittest.TestCase):
    def test_shutdown_forces_teardown_and_zeroes_leases(self):
        mgr = make_manager()
        mgr._leases = 3
        c = fake_container()
        mgr.client.containers.get.return_value = c
        mgr.shutdown()
        self.assertEqual(mgr._leases, 0)
        c.stop.assert_called_once()
        c.remove.assert_called_once()

    def test_shutdown_no_container_is_noop(self):
        mgr = make_manager()
        mgr._leases = 1
        mgr.client.containers.get.side_effect = NotFound("gone")
        mgr.shutdown()  # must not raise
        self.assertEqual(mgr._leases, 0)


# --------------------------------------------------------------------------- #
# Concurrency regression (Bug A) — no duplicate containers.run under parallel
# --------------------------------------------------------------------------- #

class TestConcurrencyBringup(unittest.TestCase):
    def test_parallel_ensure_creates_one_container(self):
        client = MagicMock()
        mgr = make_manager(client)

        created = {"count": 0}
        created_lock = threading.Lock()
        state = {"running": False}

        def fake_get(name):
            # Simulate the daemon: absent until the first run() creates it.
            if state["running"]:
                return fake_container(status="running")
            raise NotFound("absent")

        def fake_run(**kwargs):
            # If two threads reached run() concurrently the second would 409 in
            # real docker; assert that never happens by counting creations.
            with created_lock:
                created["count"] += 1
                if state["running"]:
                    raise APIError("Conflict. The container name is already in use")
                state["running"] = True
            return fake_container(status="running")

        client.containers.get.side_effect = fake_get
        client.images.get.return_value = MagicMock()
        client.containers.run.side_effect = fake_run
        # Make readiness + model trivially succeed without real HTTP.
        mgr._wait_ready = MagicMock(return_value=True)
        mgr._ensure_model = MagicMock(return_value=True)
        mgr._list_models = MagicMock(return_value=["m"])
        mgr._container_id = MagicMock(return_value="cid")

        results = []
        res_lock = threading.Lock()

        def worker():
            s = mgr.ensure_up("m")
            with res_lock:
                results.append(s)

        threads = [threading.Thread(target=worker) for _ in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        # Exactly one real creation; all 8 ensures succeed; 8 leases held.
        self.assertEqual(created["count"], 1)
        self.assertEqual(len(results), 8)
        self.assertTrue(all(r.available for r in results))
        self.assertEqual(mgr._leases, 8)


if __name__ == "__main__":
    unittest.main(verbosity=2)
