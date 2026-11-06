"""Item 4 / B16 in the graph writers: one path form, the category guard, and
each tool's own word kept beside the shared one."""
import os
import sys
import unittest
from unittest.mock import MagicMock

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, _REPO)

from graph_db.endpoint_paths import normalize_endpoint_path  # noqa: E402
from graph_db.mixins.recon.resource_mixin import ResourceMixin  # noqa: E402


class _Session:
    def __init__(self):
        self.calls = []

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def run(self, query, **params):
        self.calls.append((query, params))
        r = MagicMock()
        r.single.return_value = None
        r.__iter__ = lambda s: iter([])
        return r


class _Writer(ResourceMixin):
    def __init__(self):
        self.session = _Session()
        self.driver = MagicMock()
        self.driver.session.return_value = self.session


class TestPaths(unittest.TestCase):
    def test_one_form(self):
        self.assertEqual(normalize_endpoint_path("/docs/"), "/docs")
        self.assertEqual(normalize_endpoint_path("/"), "/")
        self.assertEqual(normalize_endpoint_path(""), "/")
        self.assertEqual(normalize_endpoint_path("api//"), "/api")

    def test_every_endpoint_writer_uses_it(self):
        for rel in ("osint_mixin.py", "graphql_mixin.py", "recon/http_mixin.py", "recon/vuln_mixin.py",
                    "recon/js_recon_mixin.py", "recon/serialized_mixin.py", "recon/ai_surface_recon_mixin.py",
                    "recon/route_exposure_mixin.py", "recon/resource_mixin.py"):
            src = open(os.path.join(_REPO, "graph_db", "mixins", rel)).read()
            self.assertIn("normalize_endpoint_path(", src, rel)


class TestResourceWriter(unittest.TestCase):
    def _write(self, endpoints):
        w = _Writer()
        recon = {"domain": "example.test", "subdomains": ["app.example.test"],
                 "resource_enum": {"by_base_url": {"https://app.example.test": {"endpoints": endpoints}}}}
        w.update_graph_from_resource_enum(recon, "u1", "p1")
        return w

    def test_b16_a_trailing_slash_is_one_node(self):
        w = self._write({"/docs/": {"methods": ["GET"], "category": "other", "sources": ["katana"]}})
        paths = {p["path"] for q, p in w.session.calls if "MERGE (e:Endpoint" in q}
        self.assertEqual(paths, {"/docs"})

    def test_category_guard_and_ffuf_category(self):
        w = self._write({"/x": {"methods": ["GET"], "category": "other", "ffuf_category": "forbidden",
                                "sources": ["ffuf"]}})
        q, p = next((q, p) for q, p in w.session.calls if "MERGE (e:Endpoint" in q)
        self.assertIn("e.category = CASE WHEN $category = 'other' AND e.category IS NOT NULL", q)
        self.assertEqual(p["ffuf_category"], "forbidden")

    def test_a_specific_parameter_type_is_kept_over_string(self):
        w = self._write({"/go": {"methods": ["GET"], "category": "dynamic", "sources": ["gau"],
                                 "parameters": {"query": [{"name": "next", "type": "string"}]}}})
        q = next(q for q, _p in w.session.calls if "MERGE (p:Parameter" in q)
        self.assertIn("p.type = CASE WHEN $param_type = 'string' AND p.type IS NOT NULL", q)


class TestJsReconCategory(unittest.TestCase):
    def test_set_on_create_and_match(self):
        src = open(os.path.join(_REPO, "graph_db", "mixins", "recon", "js_recon_mixin.py")).read()
        self.assertIn("SET e.js_recon_category = coalesce($js_recon_category, e.js_recon_category)", src)


if __name__ == "__main__":
    unittest.main()
