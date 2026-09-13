"""
Unit tests for the capture proxy's DB-file config loader + hot-reload
(RedamonCapture._read_config / _apply_config / _as_bool).

These are the security-critical paths of the "DB is the single source of truth"
refactor: the proxy reads /spool/.capture-config.json and applies it live. The
tests assert:
  - the config FILE is authoritative when present (egress + body);
  - env is only the cold-start fallback when a section is ABSENT;
  - a missing / malformed / partial file can NEVER relax the egress guard;
  - CAPTURE_BLOCKED_IPS (the service-IP denylist) is ALWAYS env-sourced, never file.

capture_addon imports mitmproxy at module load, which is not installed in the test
env, so we stub it before import. Only the pure config methods are exercised.

Run: python3 -m unittest capture_proxy.tests.test_capture_config
"""
from __future__ import annotations

import json
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# capture_addon instantiates `RedamonCapture()` at module load (the mitmdump addon
# singleton), whose __init__ mkdir's the spool/bodies dirs and starts daemon threads.
# Point those at a throwaway dir and neuter the watcher poll so importing is a no-op
# side-effect-wise. mitmproxy is stubbed (not installed in the test env).
_TMP = tempfile.mkdtemp(prefix="capcfg-test-")
os.environ.setdefault("CAPTURE_SPOOL_DIR", _TMP)
os.environ.setdefault("CAPTURE_BODIES_DIR", _TMP)
os.environ.setdefault("CAPTURE_CONFIG_FILE", os.path.join(_TMP, ".capture-config.json"))
os.environ.setdefault("CAPTURE_CONFIG_POLL_SEC", "3600")  # watcher sleeps 1h -> inert in tests
sys.modules.setdefault("mitmproxy", mock.MagicMock())
sys.modules.setdefault("mitmproxy.http", mock.MagicMock())

import capture_addon  # noqa: E402


def _new_instance(tmpdir: str):
    """Build a RedamonCapture WITHOUT running __init__ (no threads / mkdir), wired
    with just what the config methods touch."""
    inst = capture_addon.RedamonCapture.__new__(capture_addon.RedamonCapture)
    inst._config_lock = threading.Lock()
    inst.spool_dir = tmpdir
    inst.config_file = os.path.join(tmpdir, ".capture-config.json")
    inst._config_mtime = None
    return inst


class TestAsBool(unittest.TestCase):
    def test_as_bool(self):
        f = capture_addon.RedamonCapture._as_bool
        self.assertTrue(f(None, True))
        self.assertFalse(f(None, False))
        self.assertTrue(f(True))
        self.assertFalse(f(False))
        for v in ("false", "0", "no", "off", "FALSE"):
            self.assertFalse(f(v), v)
        for v in ("true", "1", "yes", "on", "x"):
            self.assertTrue(f(v), v)
        self.assertTrue(f("", True))   # empty -> default
        self.assertFalse(f("", False))


class TestReadConfig(unittest.TestCase):
    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            raw, mtime = inst._read_config()
            self.assertIsNone(raw)
            self.assertIsNone(mtime)

    def test_valid_json(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            with open(inst.config_file, "w") as fh:
                json.dump({"egress": {"block_private": False}}, fh)
            raw, mtime = inst._read_config()
            self.assertEqual(raw["egress"]["block_private"], False)
            self.assertIsNotNone(mtime)

    def test_invalid_json_fails_safe_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            with open(inst.config_file, "w") as fh:
                fh.write("{ this is not json")
            raw, mtime = inst._read_config()
            # present-but-broken -> ({}, mtime): downstream applies all-block defaults
            self.assertEqual(raw, {})
            self.assertIsNotNone(mtime)

    def test_non_dict_json_coerced_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            with open(inst.config_file, "w") as fh:
                json.dump([1, 2, 3], fh)
            raw, _ = inst._read_config()
            self.assertEqual(raw, {})


class TestApplyConfig(unittest.TestCase):
    def _apply(self, raw, env=None):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            with mock.patch.dict(os.environ, env or {}, clear=True):
                inst._apply_config(raw)
            return inst

    def test_file_egress_is_authoritative(self):
        inst = self._apply({"egress": {"block_private": False, "block_cgnat": False}})
        self.assertFalse(inst.egress_policy.block_private)
        self.assertFalse(inst.egress_policy.block_cgnat)
        self.assertTrue(inst.egress_policy.block_loopback)  # unspecified -> block

    def test_missing_egress_falls_back_to_env_block_all(self):
        # No egress section + no CAPTURE_EGRESS_* env => policy_from_env => all block.
        inst = self._apply({}, env={})
        for f in ("block_private", "block_loopback", "block_reserved", "block_cgnat"):
            self.assertTrue(getattr(inst.egress_policy, f), f)

    def test_missing_egress_uses_env_value_when_set(self):
        inst = self._apply({}, env={"CAPTURE_EGRESS_BLOCK_PRIVATE": "false"})
        self.assertFalse(inst.egress_policy.block_private)
        self.assertTrue(inst.egress_policy.block_loopback)

    def test_malformed_egress_section_falls_back_to_env(self):
        # egress present but not a dict -> treat as absent -> env fallback (block).
        inst = self._apply({"egress": "nope"}, env={})
        self.assertTrue(inst.egress_policy.block_private)

    def test_active_recording_absent_is_none(self):
        inst = self._apply({})
        self.assertIsNone(inst.active_recording)

    def test_active_recording_parsed(self):
        inst = self._apply({"active_recording": {
            "tag": "signed.tag", "scope_hosts": ["App.Target.test", " "],
            "expires_at": "2099-01-01T00:00:00Z"}})
        self.assertEqual(inst.active_recording["tag"], "signed.tag")
        self.assertEqual(inst.active_recording["scope_hosts"], ["app.target.test"])

    def test_active_recording_without_tag_ignored(self):
        inst = self._apply({"active_recording": {"scope_hosts": ["x"]}})
        self.assertIsNone(inst.active_recording)

    def test_active_recording_non_dict_ignored(self):
        self.assertIsNone(self._apply({"active_recording": "nope"}).active_recording)

    def test_empty_egress_dict_is_all_block(self):
        inst = self._apply({"egress": {}})
        self.assertTrue(inst.egress_policy.block_private)

    def test_body_policy_from_file(self):
        inst = self._apply({"body": {
            "store_bodies": False, "store_req_bodies": False, "store_resp_bodies": True,
            "max_body_kb": 128, "max_store_mb": 0, "body_rules": {"image": "disk"},
        }})
        self.assertFalse(inst.store_bodies)
        self.assertFalse(inst.store_req_bodies)
        self.assertTrue(inst.store_resp_bodies)
        self.assertEqual(inst.max_body_bytes, 128 * 1024)
        self.assertEqual(inst.max_store_bytes, 0)  # 0 = unlimited preserved
        self.assertEqual(inst.body_rules.get("image"), "disk")

    def test_body_missing_falls_back_to_env(self):
        inst = self._apply({"egress": {"block_private": False}},
                           env={"CAPTURE_PROXY_STORE_BODIES": "false",
                                "CAPTURE_PROXY_MAX_BODY_KB": "32"})
        self.assertFalse(inst.store_bodies)
        self.assertEqual(inst.max_body_bytes, 32 * 1024)

    def test_blocked_ips_always_from_env_never_file(self):
        # SECURITY: file must not be able to set/clear the service-IP denylist.
        inst = self._apply(
            {"body": {"blocked_ips": "8.8.8.8"}},   # file tries to inject -> ignored
            env={"CAPTURE_BLOCKED_IPS": "10.1.1.1,172.20.0.5"},
        )
        self.assertEqual(inst.extra_blocked_ips, ["10.1.1.1", "172.20.0.5"])

    def test_blocked_ips_empty_env_yields_empty_list(self):
        inst = self._apply({"egress": {"block_private": False}}, env={})
        self.assertEqual(inst.extra_blocked_ips, [])


class TestRecordingHelpers(unittest.TestCase):
    def test_host_in_scope_exact_and_wildcard(self):
        f = capture_addon._host_in_recording_scope
        self.assertTrue(f("app.target.test", ["app.target.test"]))
        self.assertTrue(f("app.target.test:8443", ["app.target.test"]))
        self.assertTrue(f("a.b.target.test", ["*.target.test"]))
        self.assertFalse(f("target.test", ["*.target.test"]))   # apex not matched
        self.assertFalse(f("evil.test", ["app.target.test"]))
        self.assertFalse(f("app.target.test", []))
        self.assertFalse(f("", ["app.target.test"]))

    def test_recording_expired(self):
        f = capture_addon._recording_expired
        self.assertFalse(f(None))                       # absent -> not expired
        self.assertFalse(f("garbage"))                  # unparseable -> not expired
        self.assertTrue(f("2000-01-01T00:00:00Z"))      # past
        self.assertFalse(f("2099-01-01T00:00:00Z"))     # future


class _FakeHeaders(dict):
    def pop(self, key, default=None):
        for k in list(self.keys()):
            if k.lower() == key.lower():
                return super().pop(k)
        return default


class _FakeFlow:
    def __init__(self, host, headers=None):
        self.request = mock.MagicMock()
        self.request.headers = _FakeHeaders(headers or {})
        self.request.pretty_host = host
        self.request.host = host
        self.request.port = 443
        self.metadata = {}
        self.server_conn = mock.MagicMock()


class TestRequestTagInjection(unittest.TestCase):
    """The proxy stamps the operator tag only on UNTAGGED, in-scope requests."""

    def _inst(self, active_recording):
        inst = _new_instance(tempfile.mkdtemp(prefix="capreq-"))
        inst.egress_policy = mock.MagicMock(fail_closed_on_error=True)
        inst.extra_blocked_ips = []
        inst.active_recording = active_recording
        return inst

    _AR = {"tag": "operator.signed.tag", "scope_hosts": ["app.target.test"], "expires_at": None}

    def test_untagged_in_scope_gets_operator_tag(self):
        inst = self._inst(self._AR)
        flow = _FakeFlow("app.target.test")
        with mock.patch.object(capture_addon, "check_egress", return_value=(True, None, "ok")):
            inst.request(flow)
        self.assertEqual(flow.metadata["redamon_ctx"], "operator.signed.tag")

    def test_real_tag_is_never_overridden(self):
        inst = self._inst(self._AR)
        flow = _FakeFlow("app.target.test", {"X-Redamon-Ctx": "real-recon-tag"})
        with mock.patch.object(capture_addon, "check_egress", return_value=(True, None, "ok")):
            inst.request(flow)
        self.assertEqual(flow.metadata["redamon_ctx"], "real-recon-tag")

    def test_out_of_scope_stays_untagged(self):
        inst = self._inst(self._AR)
        flow = _FakeFlow("unrelated.test")
        with mock.patch.object(capture_addon, "check_egress", return_value=(True, None, "ok")):
            inst.request(flow)
        self.assertIsNone(flow.metadata["redamon_ctx"])

    def test_no_active_recording_stays_untagged(self):
        inst = self._inst(None)
        flow = _FakeFlow("app.target.test")
        with mock.patch.object(capture_addon, "check_egress", return_value=(True, None, "ok")):
            inst.request(flow)
        self.assertIsNone(flow.metadata["redamon_ctx"])

    def test_expired_recording_stays_untagged(self):
        inst = self._inst({**self._AR, "expires_at": "2000-01-01T00:00:00Z"})
        flow = _FakeFlow("app.target.test")
        with mock.patch.object(capture_addon, "check_egress", return_value=(True, None, "ok")):
            inst.request(flow)
        self.assertIsNone(flow.metadata["redamon_ctx"])


class _StopLoop(BaseException):
    """Break _config_watch's `while True` from a patched time.sleep (BaseException so
    the loop's `except Exception` guard does not swallow it)."""


def _write_json(path, obj):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh)


class TestReadConfigEdges(unittest.TestCase):
    def test_directory_at_config_path_is_treated_as_absent(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            os.makedirs(inst.config_file)  # a DIRECTORY where the file should be
            raw, sig = inst._read_config()
            # open() raises OSError -> (None, None) -> env fallback (fail-safe block)
            self.assertIsNone(raw)
            self.assertIsNone(sig)

    def test_non_utf8_bytes_fail_safe_to_empty(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            with open(inst.config_file, "wb") as fh:
                fh.write(b"\xff\xfe\x00garbage")
            raw, sig = inst._read_config()
            self.assertEqual(raw, {})          # undecodable -> fail-safe defaults
            self.assertIsNotNone(sig)

    def test_signature_is_content_not_mtime(self):
        # Two files with identical content have identical signatures (change detection
        # is by content, so a same-content rewrite is a no-op).
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            _write_json(inst.config_file, {"egress": {"block_private": False}})
            _, sig1 = inst._read_config()
            _write_json(inst.config_file, {"egress": {"block_private": False}})
            _, sig2 = inst._read_config()
            self.assertEqual(sig1, sig2)


class TestConfigWatch(unittest.TestCase):
    def _run_watch_once(self, inst, iterations_before_stop=1):
        """Drive `iterations_before_stop` real iterations, then break the loop."""
        state = {"n": 0}

        def fake_sleep(_):
            state["n"] += 1
            if state["n"] > iterations_before_stop:
                raise _StopLoop
        with mock.patch.object(capture_addon.time, "sleep", fake_sleep), \
             mock.patch.dict(os.environ, {}, clear=True):
            try:
                inst._config_watch()
            except _StopLoop:
                pass

    def test_hot_reload_on_content_change(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            _write_json(inst.config_file, {"egress": {"block_private": True}})
            raw, sig = inst._read_config()
            inst._apply_config(raw)
            inst._config_sig = sig
            self.assertTrue(inst.egress_policy.block_private)
            # operator flips it in the DB -> reconciler rewrites the file
            _write_json(inst.config_file, {"egress": {"block_private": False}})
            self._run_watch_once(inst)
            self.assertFalse(inst.egress_policy.block_private)  # applied LIVE

    def test_no_reapply_when_unchanged(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            _write_json(inst.config_file, {"egress": {"block_private": False}})
            raw, sig = inst._read_config()
            inst._apply_config(raw)
            inst._config_sig = sig
            with mock.patch.object(inst, "_apply_config") as spy:
                self._run_watch_once(inst)
                spy.assert_not_called()  # signature unchanged -> no re-apply

    def test_watch_survives_read_error(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            _write_json(inst.config_file, {"egress": {"block_private": False}})
            raw, sig = inst._read_config()
            inst._apply_config(raw)
            inst._config_sig = sig
            with mock.patch.object(inst, "_read_config", side_effect=RuntimeError("boom")):
                # must not raise; keeps the already-applied config
                self._run_watch_once(inst)
            self.assertFalse(inst.egress_policy.block_private)

    def test_file_deleted_then_reappears_reapplies(self):
        with tempfile.TemporaryDirectory() as d:
            inst = _new_instance(d)
            _write_json(inst.config_file, {"egress": {"block_private": False}})
            raw, sig = inst._read_config()
            inst._apply_config(raw)
            inst._config_sig = sig
            os.remove(inst.config_file)                  # vanish -> signature None
            _write_json(inst.config_file, {"egress": {"block_private": True}})  # returns changed
            self._run_watch_once(inst)
            self.assertTrue(inst.egress_policy.block_private)


if __name__ == "__main__":
    unittest.main()
