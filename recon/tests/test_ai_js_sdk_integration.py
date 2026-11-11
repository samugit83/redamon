"""Integration test for Phase 6 — end-to-end js_recon AI SDK pass.

This is one tier above unit tests: it exercises the actual ``_run_analysis``
function from ``recon.main_recon_modules.js_recon`` with a stubbed js_files
list and an entire settings dict, then verifies the contract that the
``js_recon_mixin`` consumes:

  - ``results['ai_sdk_findings']`` is present
  - every entry has all the keys the mixin reads (``id`` is appended by the
    caller in js_recon.py, not by the helper)
  - turning the toggle off yields zero ai_sdk_findings
  - turning the toggle on populates findings for every analyzed file
  - findings are deterministic across re-runs (same id / byte_offset)

The recon helpers package ``__init__.py`` pulls in DNS / Docker dependencies
that aren't present in a slim test image, so this test imports the analysis
function via the same ``importlib.util.spec_from_file_location`` trick used
elsewhere — no package side-effects.
"""
from __future__ import annotations

import hashlib
import importlib.util
import os
import sys
import types
import unittest


_HERE = os.path.dirname(os.path.abspath(__file__))
_REPO_ROOT = os.path.normpath(os.path.join(_HERE, "..", ".."))


def _import_js_recon():
    """Load js_recon.py in a way that bypasses the heavyweight package init.

    We pre-populate ``sys.modules['recon.helpers.ai_signal_catalog']`` so the
    inline ``from recon.helpers.ai_signal_catalog import match_ai_sdk`` works
    without dragging in the rest of ``recon.helpers`` (which needs DNS, etc.).
    Then we synthesise minimal stub modules for the rest of js_recon's
    imports — they aren't exercised by ``_run_analysis`` when their toggles
    are off.
    """
    # Stub the heavy helpers package so attribute lookups don't try to load
    # security_checks.py et al.
    if "recon" not in sys.modules:
        sys.modules["recon"] = types.ModuleType("recon")
    if "recon.helpers" not in sys.modules:
        helpers = types.ModuleType("recon.helpers")
        sys.modules["recon.helpers"] = helpers
        sys.modules["recon"].helpers = helpers  # type: ignore[attr-defined]

    # Provide a real ai_signal_catalog module under the recon.helpers namespace
    # so the inline import path resolves to our patterns / match_ai_sdk.
    spec = importlib.util.spec_from_file_location(
        "recon.helpers.ai_signal_catalog",
        os.path.join(_REPO_ROOT, "recon", "helpers", "ai_signal_catalog.py"),
    )
    catalog = importlib.util.module_from_spec(spec)
    sys.modules["recon.helpers.ai_signal_catalog"] = catalog
    spec.loader.exec_module(catalog)

    # js_recon imports the RoE matcher at module level; it needs only the
    # stdlib, so load the real one the same way.
    spec = importlib.util.spec_from_file_location(
        "recon.helpers.roe_scope",
        os.path.join(_REPO_ROOT, "recon", "helpers", "roe_scope.py"),
    )
    roe_scope = importlib.util.module_from_spec(spec)
    sys.modules["recon.helpers.roe_scope"] = roe_scope
    spec.loader.exec_module(roe_scope)

    # The catch-all control helper needs only the stdlib and roe_scope.
    spec = importlib.util.spec_from_file_location(
        "recon.helpers.catchall",
        os.path.join(_REPO_ROOT, "recon", "helpers", "catchall.py"),
    )
    catchall = importlib.util.module_from_spec(spec)
    sys.modules["recon.helpers.catchall"] = catchall
    sys.modules["recon.helpers"].catchall = catchall  # type: ignore[attr-defined]
    spec.loader.exec_module(catchall)

    # The process-wide RoE request clock needs only the stdlib (inert here: no ceiling).
    spec = importlib.util.spec_from_file_location(
        "recon.helpers.request_pacer",
        os.path.join(_REPO_ROOT, "recon", "helpers", "request_pacer.py"),
    )
    request_pacer = importlib.util.module_from_spec(spec)
    sys.modules["recon.helpers.request_pacer"] = request_pacer
    sys.modules["recon.helpers"].request_pacer = request_pacer  # type: ignore[attr-defined]
    spec.loader.exec_module(request_pacer)

    # Stub the other helpers js_recon needs at import time. We toggle every
    # non-AI analysis pass OFF in the settings so these stubs never execute.
    for name in (
        "patterns", "validators", "sourcemap", "dependency",
        "endpoints", "framework", "trufflehog_bridge", "hop_guard",
    ):
        mod = types.ModuleType(f"recon.helpers.js_recon.{name}")
        sys.modules[f"recon.helpers.js_recon.{name}"] = mod
    js_recon_pkg = types.ModuleType("recon.helpers.js_recon")
    sys.modules["recon.helpers.js_recon"] = js_recon_pkg
    # js_recon imports this one as a module (`from recon.helpers.js_recon import
    # trufflehog_bridge`), so the package must carry it.
    js_recon_pkg.trufflehog_bridge = sys.modules["recon.helpers.js_recon.trufflehog_bridge"]

    # What counts as a JS file decides which files reach the AI-SDK matcher, and it
    # needs only the stdlib, so load the real one.
    spec = importlib.util.spec_from_file_location(
        "recon.helpers.js_recon.urls",
        os.path.join(_REPO_ROOT, "recon", "helpers", "js_recon", "urls.py"),
    )
    js_urls = importlib.util.module_from_spec(spec)
    sys.modules["recon.helpers.js_recon.urls"] = js_urls
    spec.loader.exec_module(js_urls)

    # Minimal symbols js_recon.py imports from each.
    sys.modules["recon.helpers.js_recon.patterns"].SUPERSEDED_BY_TRUFFLEHOG = frozenset()
    sys.modules["recon.helpers.js_recon.patterns"].scan_js_content = lambda *a, **kw: ([], {})
    sys.modules["recon.helpers.js_recon.patterns"].scan_dev_comments = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.patterns"].load_custom_patterns = lambda *a, **kw: None
    sys.modules["recon.helpers.js_recon.validators"].validate_secret = lambda *a, **kw: {}
    hop_guard = sys.modules["recon.helpers.js_recon.hop_guard"]
    hop_guard.UNSAFE, hop_guard.ROE_EXCLUDED, hop_guard.TOO_MANY_REDIRECTS = "unsafe", "roe_excluded", "too_many_redirects"
    hop_guard.REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
    hop_guard.fetch_hop_by_hop = lambda *a, **kw: None
    hop_guard.admit_any = lambda url: True
    # IP-mode admission is read by run_js_recon only, never by _run_analysis.
    target_admission = types.ModuleType("recon.helpers.target_admission")
    target_admission.ip_mode_url_admission = lambda *a, **kw: None
    sys.modules["recon.helpers.target_admission"] = target_admission
    sys.modules["recon.helpers.js_recon.sourcemap"].discover_and_analyze_sourcemaps = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.sourcemap"].pseudo_file_base = lambda map_url, js_url: js_url or map_url
    sys.modules["recon.helpers.js_recon.dependency"].detect_dependency_confusion = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.endpoints"].extract_endpoints = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.framework"].detect_frameworks = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.framework"].detect_dom_sinks = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.framework"].detect_dev_comments = lambda *a, **kw: []
    sys.modules["recon.helpers.js_recon.framework"].load_custom_frameworks = lambda *a, **kw: None

    # js_recon imports is_url_safe_to_probe and is_address_safe_to_scan from
    # recon.main_recon_modules.ip_filter (falling back to a bare `ip_filter`). Stub
    # both so the address guards are a no-op in the test (every target is safe).
    mrm_pkg = types.ModuleType("recon.main_recon_modules")
    mrm_pkg.__path__ = []  # mark as a package so submodule imports resolve
    sys.modules["recon.main_recon_modules"] = mrm_pkg
    sys.modules["recon"].main_recon_modules = mrm_pkg  # type: ignore[attr-defined]
    _ip_filter = types.ModuleType("ip_filter")
    _ip_filter.is_url_safe_to_probe = lambda *a, **kw: True
    _ip_filter.is_address_safe_to_scan = lambda *a, **kw: True
    sys.modules["ip_filter"] = _ip_filter
    sys.modules["recon.main_recon_modules.ip_filter"] = _ip_filter

    # Now load js_recon itself.
    spec = importlib.util.spec_from_file_location(
        "recon.main_recon_modules.js_recon",
        os.path.join(_REPO_ROOT, "recon", "main_recon_modules", "js_recon.py"),
    )
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


# Lazy import — only happens when a test class instantiates.
_jsr = None
def jsr():
    global _jsr
    if _jsr is None:
        _jsr = _import_js_recon()
    return _jsr


def _make_settings(ai_on: bool = True) -> dict:
    """Settings dict that turns every non-AI analysis pass off so the
    integration test isolates the new AI pass."""
    return {
        "JS_RECON_REGEX_PATTERNS": False,
        "JS_RECON_SOURCE_MAPS": False,
        "JS_RECON_DEPENDENCY_CHECK": False,
        "JS_RECON_EXTRACT_ENDPOINTS": False,
        "JS_RECON_FRAMEWORK_DETECT": False,
        "JS_RECON_DOM_SINKS": False,
        "JS_RECON_DEV_COMMENTS": False,
        "JS_RECON_TRUFFLEHOG_ENABLED": False,
        "JS_RECON_AI_SDK_DETECTION_ENABLED": ai_on,
        "JS_RECON_TIMEOUT": 30,
        "JS_RECON_MIN_CONFIDENCE": "low",
    }


SAMPLE_BUNDLE = (
    'import { OpenAI } from "openai";\n'
    'import Anthropic from "@anthropic-ai/sdk";\n'
    'const c = new OpenAI({ apiKey: "sk-proj-'
    + "a" * 40 + "T3BlbkFJ" + "b" * 40 + '", '
    'dangerouslyAllowBrowser: !0 });\n'
    'fetch("https://api.openai.com/v1/chat/completions");\n'
    'window.gradio_config = {};\n'
)


class IntegrationToggleOff(unittest.TestCase):
    def test_no_findings_when_toggle_off(self):
        js_files = [{"content": SAMPLE_BUNDLE, "url": "https://x.example.com/app.js"}]
        results = jsr()._run_analysis(js_files, _make_settings(ai_on=False))
        self.assertEqual(results.get("ai_sdk_findings", []), [])


class IntegrationToggleOn(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.js_files = [
            {"content": SAMPLE_BUNDLE, "url": "https://x.example.com/app.js"},
            {"content": 'import "@langchain/openai";', "url": "https://x.example.com/vendor.js"},
        ]
        cls.results = jsr()._run_analysis(cls.js_files, _make_settings(ai_on=True))
        cls.findings = cls.results["ai_sdk_findings"]

    def test_findings_populated(self):
        self.assertGreater(len(self.findings), 0,
            f"Expected ai_sdk_findings to be non-empty when toggle on, got 0")

    def test_every_finding_has_caller_metadata(self):
        """The caller in js_recon.py is responsible for stamping `id` and
        `source_url` on each finding from match_ai_sdk. Verify both fields
        appear and the ID is a stable hash."""
        for f in self.findings:
            self.assertIn("id", f, f"Missing 'id' on {f}")
            self.assertTrue(f["id"].startswith("ai-sdk-"),
                f"ID must start with 'ai-sdk-' prefix; got {f['id']}")
            self.assertEqual(len(f["id"]), len("ai-sdk-") + 16,
                f"ID must be 'ai-sdk-' + 16-hex; got {f['id']}")
            self.assertIn("source_url", f)
            self.assertTrue(f["source_url"].startswith("https://"))

    def test_mixin_required_fields_present(self):
        """The js_recon_mixin reads these fields off each finding when it
        writes the JsReconFinding node. Contract test for that interface."""
        required = {
            "id", "category", "sdk_name", "severity", "confidence",
            "matched_text", "sample", "byte_offset", "detection_method",
            "source_url",
        }
        for f in self.findings:
            missing = required - set(f.keys())
            self.assertFalse(missing,
                f"Mixin contract: missing keys {missing} on {f}")

    def test_captured_value_for_key_literals_only(self):
        """captured_value (the dedup needle the mixin uses) is non-empty only
        on key-literal findings. Other categories may have it empty/absent."""
        for f in self.findings:
            cv = f.get("captured_value", "")
            if f["category"] == "ai-sdk-key-literal":
                self.assertTrue(cv, f"key literal missing captured_value: {f}")
                self.assertGreaterEqual(len(cv), 12)

    def test_ids_are_deterministic_across_runs(self):
        """Re-running the analysis on the same input produces identical IDs.
        This is the idempotency contract for Neo4j MERGE."""
        run2 = jsr()._run_analysis(self.js_files, _make_settings(ai_on=True))
        ids1 = sorted(f["id"] for f in self.findings)
        ids2 = sorted(f["id"] for f in run2["ai_sdk_findings"])
        self.assertEqual(ids1, ids2)

    def test_ids_differ_across_source_urls(self):
        """Two files with the same content produce DIFFERENT ids because the
        sig includes source_url. Catches the collision risk the reviewer
        flagged."""
        js_files = [
            {"content": SAMPLE_BUNDLE, "url": "https://x.example.com/a.js"},
            {"content": SAMPLE_BUNDLE, "url": "https://x.example.com/b.js"},
        ]
        results = jsr()._run_analysis(js_files, _make_settings(ai_on=True))
        ids_a = {f["id"] for f in results["ai_sdk_findings"]
                 if f["source_url"].endswith("/a.js")}
        ids_b = {f["id"] for f in results["ai_sdk_findings"]
                 if f["source_url"].endswith("/b.js")}
        self.assertTrue(ids_a)
        self.assertTrue(ids_b)
        self.assertEqual(ids_a & ids_b, set(),
            "Identical content under different URLs must produce different IDs")


class IntegrationSummary(unittest.TestCase):
    """The _build_summary helper rolls the AI findings into the metrics block
    that the webapp / agent / Cypher report stages consume."""

    def test_summary_counts_match(self):
        js_files = [{"content": SAMPLE_BUNDLE, "url": "https://x.example.com/a.js"}]
        results = jsr()._run_analysis(js_files, _make_settings(ai_on=True))
        summary = jsr()._build_summary(results)
        total = summary["ai_sdk_findings_total"]
        self.assertEqual(total, len(results["ai_sdk_findings"]))
        by_cat = summary["ai_sdk_findings_by_category"]
        self.assertEqual(sum(by_cat.values()), total)
        by_sev = summary["ai_sdk_findings_by_severity"]
        self.assertEqual(sum(by_sev.values()), total)


class IntegrationEmptyJsFiles(unittest.TestCase):
    def test_no_js_files(self):
        results = jsr()._run_analysis([], _make_settings(ai_on=True))
        self.assertEqual(results.get("ai_sdk_findings", []), [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
