"""
Unit tests for ResourceMixin.update_graph_from_resource_enum's handling of
the `sources` (plural) array on Endpoint nodes.

These tests verify the Issue 2 fix: the graph mixin must persist the
fine-grained `sources` list set by each crawler's merge_X_into_by_base_url
helper, not throw it away. Critical for queries like:

    MATCH (e:Endpoint)
    WHERE 'zap_ajax_spider' IN e.sources
    RETURN e.url
"""

from __future__ import annotations

import os
import sys
import unittest
from pathlib import Path
from unittest.mock import MagicMock

_PROJECT_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_PROJECT_ROOT))

from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402


_RECON_JOB_PARAMS = {
    "recon_job_id": "job-resource-sources-123",
    "recon_job_started_at": "2026-07-24T10:11:12Z",
}


def _make_mixin_with_captured_session():
    """
    Build a ResourceMixin-using class plus a session mock whose every
    ``session.run`` call appends ``(query, kwargs)`` to a captured list.
    """
    captured: list[tuple[str, dict]] = []

    session = MagicMock()

    def fake_run(query, **kwargs):
        captured.append((query, kwargs))
        result = MagicMock()
        result.single.return_value = (
            {"linked": 0}
            if "RETURN count(*) AS linked" in query
            else None
        )
        result.__iter__ = lambda self: iter([])
        return result

    session.run = fake_run

    driver = MagicMock()
    driver.session.return_value.__enter__ = MagicMock(return_value=session)
    driver.session.return_value.__exit__ = MagicMock(return_value=False)

    class _Client(ResourceMixin):
        def __init__(self):
            self.driver = driver

        def _recon_job_params(self):
            return dict(_RECON_JOB_PARAMS)

    return _Client(), captured


def _recon_data_for(endpoint_sources_by_path: dict[str, list[str]]) -> dict:
    """Build a minimal recon_data shaped like resource_enum output."""
    endpoints = {}
    for path, sources in endpoint_sources_by_path.items():
        endpoints[path] = {
            "path": path,
            "methods": ["GET"],
            "full_url": f"http://app.example.com{path}",
            "has_parameters": False,
            "category": "other",
            "sources": sources,
            "parameters": {"query": [], "body": [], "path": []},
            "parameter_count": {"query": 0, "body": 0, "path": 0, "total": 0},
            "sample_urls": [f"http://app.example.com{path}"],
            "urls_found": 1,
        }
    return {
        "domain": "app.example.com",
        "subdomains": ["app.example.com"],
        "resource_enum": {
            "by_base_url": {
                "http://app.example.com": {
                    "base_url": "http://app.example.com",
                    "endpoints": endpoints,
                    "summary": {
                        "total_endpoints": len(endpoints),
                        "total_parameters": 0,
                        "methods": {"GET": len(endpoints)},
                        "categories": {"other": len(endpoints)},
                    },
                },
            },
            "forms": [],
            "scan_metadata": {},
            "summary": {
                "total_endpoints": len(endpoints),
                "total_base_urls": 1,
            },
            "external_domains": [],
        },
    }


def _endpoint_runs(captured):
    """Filter captured session.run calls to just the Endpoint MERGE."""
    return [
        (q, p) for (q, p) in captured
        if "MERGE (e:Endpoint" in q and "SET e.user_id" in q
    ]


class TestResourceMixinSourcesPersistence(unittest.TestCase):
    """Verify the `sources` array reaches Cypher and the union logic is right."""

    def test_zap_ajax_spider_sources_reaches_cypher(self):
        """The literal `zap_ajax_spider` tag from the helper must arrive in $sources."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/users": ["zap_ajax_spider"]})

        stats = client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        self.assertEqual(stats["errors"], [])
        ep_runs = _endpoint_runs(captured)
        self.assertEqual(len(ep_runs), 1)
        query, params = ep_runs[0]
        self.assertEqual(params.get("sources"), ["zap_ajax_spider"])
        self.assertEqual(
            params.get("recon_job_id"),
            _RECON_JOB_PARAMS["recon_job_id"],
        )
        self.assertEqual(
            params.get("recon_job_started_at"),
            _RECON_JOB_PARAMS["recon_job_started_at"],
        )
        self.assertIn(
            "e.first_seen = coalesce("
            "e.first_seen, datetime($recon_job_started_at))",
            query,
        )
        self.assertIn(
            "e.first_seen_job_id = coalesce("
            "e.first_seen_job_id, $recon_job_id)",
            query,
        )
        self.assertIn(
            "e.last_seen = datetime($recon_job_started_at)",
            query,
        )
        self.assertIn("e.last_seen_job_id = $recon_job_id", query)

    def test_katana_sources_reaches_cypher(self):
        """Sanity: same path works for any crawler tag, not just ZAP."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/projects": ["katana"]})

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), ["katana"])

    def test_multi_tool_overlap_passes_full_list(self):
        """When a helper merges two tools' findings into one endpoint, both must persist."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for(
            {"/api/orders": ["katana", "zap_ajax_spider"]}
        )

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(
            sorted(params.get("sources") or []),
            sorted(["katana", "zap_ajax_spider"]),
        )

    def test_missing_sources_defaults_to_empty_list(self):
        """Endpoints without a sources field should send [] (not None) to Cypher."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/foo": []})
        # Pop the sources entirely to simulate a malformed helper output
        del recon_data["resource_enum"]["by_base_url"][
            "http://app.example.com"]["endpoints"]["/api/foo"]["sources"]

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), [])

    def test_cypher_uses_union_pattern_not_overwrite(self):
        """The Cypher must use the CASE/union pattern so re-runs don't clobber existing sources."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/x": ["zap_ajax_spider"]})

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        query, _ = _endpoint_runs(captured)[0]
        # Confirms the patched merge-not-clobber semantics are present.
        self.assertIn("e.sources = CASE", query)
        self.assertIn("WHEN e.sources IS NULL THEN $sources", query)
        self.assertIn(
            "e.sources + [s IN $sources WHERE NOT s IN e.sources]",
            query,
        )

    def test_singular_source_still_set_for_phase_bucket(self):
        """Backward compat: `e.source = 'resource_enum'` must still be in the SET."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/y": ["zap_ajax_spider"]})

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        query, _ = _endpoint_runs(captured)[0]
        self.assertIn("e.source = 'resource_enum'", query)

    # ----- Defensive normalisation (Python-side) -----

    def test_dedup_on_first_write(self):
        """Sloppy helper output with dupes must not leak duplicates on first MERGE.
        The Cypher CASE branch only dedups against EXISTING sources on subsequent
        merges, so first-write dedup has to happen in Python."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for(
            {"/api/x": ["katana", "katana", "zap_ajax_spider", "katana"]}
        )

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), ["katana", "zap_ajax_spider"])

    def test_dedup_preserves_order(self):
        """Order matters for downstream queries that rank by first-discovered."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for(
            {"/api/x": ["zap_ajax_spider", "katana", "zap_ajax_spider"]}
        )

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), ["zap_ajax_spider", "katana"])

    def test_none_values_filtered(self):
        """A None mixed into the sources list must not reach Cypher."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/x": ["katana"]})
        # Inject a None after recon_data is built
        ep = recon_data["resource_enum"]["by_base_url"][
            "http://app.example.com"]["endpoints"]["/api/x"]
        ep["sources"] = ["katana", None, "zap_ajax_spider", None]

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), ["katana", "zap_ajax_spider"])

    def test_empty_strings_filtered(self):
        """Defensive: blanks shouldn't pollute the source list."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/x": ["katana"]})
        ep = recon_data["resource_enum"]["by_base_url"][
            "http://app.example.com"]["endpoints"]["/api/x"]
        ep["sources"] = ["", "katana", "  ", "zap_ajax_spider"]

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        # "  " (whitespace-only) is truthy in Python, so it survives the `if s`
        # check. The dict.fromkeys dedup keeps it as a distinct key. This test
        # documents the current contract — sources are NOT trimmed; the caller
        # is responsible for sending clean tokens.
        self.assertIn("katana", params.get("sources"))
        self.assertIn("zap_ajax_spider", params.get("sources"))
        self.assertNotIn("", params.get("sources"))

    def test_non_string_values_filtered(self):
        """Defensive: ints/dicts/objects accidentally ending up in sources are dropped."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/x": ["katana"]})
        ep = recon_data["resource_enum"]["by_base_url"][
            "http://app.example.com"]["endpoints"]["/api/x"]
        ep["sources"] = ["katana", 42, {"name": "katana"}, "zap_ajax_spider"]

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), ["katana", "zap_ajax_spider"])

    def test_idempotency_same_crawler_twice_in_one_call(self):
        """If a helper accidentally emits the same source twice, it's collapsed once."""
        client, captured = _make_mixin_with_captured_session()
        recon_data = _recon_data_for({"/api/x": ["zap_ajax_spider", "zap_ajax_spider"]})

        client.update_graph_from_resource_enum(recon_data, "u1", "p1")

        _query, params = _endpoint_runs(captured)[0]
        self.assertEqual(params.get("sources"), ["zap_ajax_spider"])


if __name__ == "__main__":
    unittest.main()
