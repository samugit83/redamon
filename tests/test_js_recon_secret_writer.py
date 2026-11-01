"""What the JS Recon writer stores on a Secret node (plan 05).

The detector computes a masked context and flags keys that are public by
design; the writer must put both on the node, with the context capped.
"""

import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)

sys.modules.setdefault("neo4j", MagicMock())
sys.modules.setdefault("dotenv", MagicMock())

from graph_db.mixins.recon.js_recon_mixin import JsReconMixin  # noqa: E402


class _Result:
    def single(self):
        return {"linked": 0, "created": True, "enriched": 0}


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        return _Result()


class _Client(JsReconMixin):
    def __init__(self):
        self.session_obj = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session_obj


def _secret(**overrides) -> dict:
    secret = {
        "id": "abc123", "name": "AWS Access Key ID", "matched_text": "AKIAQ7R2M9X4K1T8B3V6",
        "redacted_value": "AKIAQ7...B3V6", "severity": "critical", "confidence": "high",
        "category": "cloud", "line_number": 1,
        "source_url": "https://app.example.com/static/main.js",
        "validation": {"status": "unvalidated"},
    }
    secret.update(overrides)
    return secret


def _secret_write(secret: dict) -> tuple:
    client = _Client()
    client.update_graph_from_js_recon({
        "domain": "example.com",
        "js_recon": {"scan_metadata": {"scan_timestamp": "2026-10-24T00:00:00Z"},
                     "secrets": [secret]},
    }, "u1", "p1")
    for query, kwargs in client.session_obj.calls:
        if "MERGE (s:Secret" in query:
            return query, kwargs
    raise AssertionError("no Secret write")


class TestSecretContext(unittest.TestCase):
    def test_the_context_is_written(self):
        query, kwargs = _secret_write(_secret(context="const k = 'AKIAQ7...B3V6';"))
        self.assertIn("s.context = $context", query)
        self.assertEqual(kwargs["context"], "const k = 'AKIAQ7...B3V6';")

    def test_the_context_is_capped_at_400_characters(self):
        _, kwargs = _secret_write(_secret(context="x" * 1000))
        self.assertEqual(len(kwargs["context"]), 400)

    def test_a_missing_context_is_stored_empty(self):
        _, kwargs = _secret_write(_secret())
        self.assertEqual(kwargs["context"], "")


class TestPublicClientKeyFlag(unittest.TestCase):
    def test_a_public_key_is_written_at_info_with_the_flag(self):
        query, kwargs = _secret_write(_secret(
            name="GCP API Key", severity="info", public_client_key=True,
            matched_text="AIzaSy8Kq2Lm7Zx4Wp9Rt1Vb6Nc3Hd5Jf0Gs2Ue"))
        self.assertIn("s.public_client_key = $public_client_key", query)
        self.assertIs(kwargs["public_client_key"], True)
        self.assertEqual(kwargs["severity"], "info")

    def test_any_other_secret_is_written_false(self):
        _, kwargs = _secret_write(_secret())
        self.assertIs(kwargs["public_client_key"], False)


if __name__ == "__main__":
    unittest.main()


class _Rows(_Result):
    def __init__(self, rows=(), kept=0):
        self.rows, self.kept = list(rows), kept

    def __iter__(self):
        return iter(self.rows)

    def single(self):
        return {"linked": 0, "created": True, "enriched": 0, "kept": self.kept}


class _StoredSession(_Session):
    """A session holding what an earlier run wrote on the Secret nodes."""

    def __init__(self, stored=()):
        super().__init__()
        self.stored = list(stored)

    def run(self, query, **kwargs):
        self.calls.append((query, kwargs))
        if "RETURN s.id AS id, s.alternate_names" in query:
            return _Rows(self.stored)
        if "detection_method: 'trufflehog'" in query and "SET s.updated_at" in query:
            return _Rows(kept=2)
        return _Rows()


def _write(secrets, trufflehog=None, stored=()):
    client = _Client()
    client.session_obj = _StoredSession(stored)
    client.driver.session.return_value = client.session_obj
    meta = {"scan_timestamp": "2026-11-01T00:00:00Z"}
    if trufflehog is not None:
        meta["trufflehog"] = trufflehog
    stats = client.update_graph_from_js_recon(
        {"domain": "example.com", "js_recon": {"scan_metadata": meta, "secrets": secrets}}, "u1", "p1")
    return client.session_obj.calls, stats


def _secret_writes(calls):
    return [kw for q, kw in calls if "MERGE (s:Secret" in q]


def _keep_alive(calls):
    return [(q, kw) for q, kw in calls if "detection_method: 'trufflehog'" in q and "SET s.updated_at" in q]


GH = "gh" + "p_" + "Qx7Lm2Rt9Wn4Yb1Vc6Hd3Jf5Gs8Ae0Ui2Ko4"
TH_INFO = {"detector": "Github", "verified": True, "error_class": "", "extra": {"version": "2"}}


class TestLineAndAlternateNames(unittest.TestCase):
    def test_written_for_every_secret(self):
        query, kwargs = _secret_write(_secret(line_number=7, alternate_names=["Generic Secret"]))
        self.assertIn("s.line_number = $line_number", query)
        self.assertIn("s.alternate_names = $alternate_names", query)
        self.assertEqual((kwargs["line_number"], kwargs["alternate_names"]), (7, ["Generic Secret"]))

    def test_absent_values_are_none_and_empty(self):
        _, kwargs = _secret_write(_secret(line_number=None))
        self.assertIsNone(kwargs["line_number"])
        self.assertEqual(kwargs["alternate_names"], [])


class TestTruffleHogFindings(unittest.TestCase):
    def test_detection_method_and_validation_info_without_a_value(self):
        secret = _secret(id="th1", name="GitHub Token Classic", matched_text=GH, detection_method="trufflehog",
                         validation={"status": "validated", "valid": True, "checked_by": "trufflehog",
                                     "trufflehog": TH_INFO})
        (kw,) = _secret_writes(_write([secret], {"status": "ran"})[0])
        self.assertEqual(kw["detection_method"], "trufflehog")
        info = __import__("json").loads(kw["validation_info"])
        self.assertEqual(info["trufflehog"], TH_INFO)
        self.assertNotIn(GH, kw["validation_info"])

    def test_no_keep_alive_when_trufflehog_ran_or_is_off(self):
        for trufflehog in ({"status": "ran"}, None):
            calls, _ = _write([_secret()], trufflehog)
            self.assertEqual(_keep_alive(calls), [])
            self.assertFalse(any("RETURN s.id AS id, s.alternate_names" in q for q, _ in calls))

    def test_a_failed_run_keeps_its_own_findings_alive_tenant_scoped(self):
        urls = ["https://app.example.com/static/main.js", "upload://keys.js"]
        calls, stats = _write([_secret()], {"status": "failed", "reason": "exit 1", "analyzed_urls": urls})
        ((query, kw),) = _keep_alive(calls)
        self.assertIn("user_id: $uid, project_id: $pid, source: 'js_recon'", query)
        self.assertIn("detection_method: 'trufflehog'", query)
        self.assertIn("WHERE s.source_url IN $analyzed_urls", query)
        self.assertEqual((kw["uid"], kw["pid"], kw["analyzed_urls"]), ("u1", "p1", urls))
        self.assertEqual(stats["trufflehog_kept_alive"], 2)

    def test_regex_findings_are_not_kept_alive(self):
        calls, _ = _write([_secret()], {"status": "timed_out", "analyzed_urls": ["https://a/x.js"]})
        ((query, _),) = _keep_alive(calls)
        self.assertNotIn("detection_method: 'regex'", query)
        self.assertNotIn("detection_method IN", query)

    def test_a_matched_node_keeps_what_trufflehog_said_earlier(self):
        import json
        node_id = "secret-u1-p1-abc123"
        stored = [{"id": node_id, "alternate_names": ["Clerk Secret Key", "TruffleHog:AWS"],
                   "validation_info": json.dumps({"status": "validated", "trufflehog": TH_INFO})}]
        secret = _secret(alternate_names=["Generic API Key"], validation={"status": "unknown"})
        calls, _ = _write([secret], {"status": "skipped", "reason": "image_missing", "analyzed_urls": []},
                          stored=stored)
        (kw,) = _secret_writes(calls)
        self.assertEqual(kw["alternate_names"], ["Generic API Key", "TruffleHog:AWS"])
        info = json.loads(kw["validation_info"])
        self.assertEqual(info["status"], "unknown")
        self.assertEqual(info["trufflehog"], TH_INFO)
        (read_q, read_kw), = [(q, k) for q, k in calls if "RETURN s.id AS id, s.alternate_names" in q]
        self.assertIn("user_id: $uid, project_id: $pid", read_q)
        self.assertEqual(read_kw["ids"], [node_id])
